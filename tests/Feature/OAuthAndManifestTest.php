<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestValidator;
use Padosoft\Iam\Domain\Applications\Models\Application;
use Padosoft\Iam\Domain\Applications\Models\Manifest;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\OAuth\Entities\AccessTokenEntity;
use Padosoft\Iam\Domain\OAuth\Entities\RefreshTokenEntity;
use Padosoft\Iam\Domain\OAuth\Models\OauthAccessToken;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Models\OauthRefreshToken;
use Padosoft\Iam\Domain\OAuth\Models\OauthTokenChain;
use Padosoft\Iam\Domain\OAuth\Repositories\RefreshTokenRepository;
use Padosoft\Iam\Domain\OAuth\Token\AccessTokenClaims;
use Tests\TestCase;

/**
 * Prova end-to-end di due sottosistemi del server Laravel IAM:
 *  - Application Registry + Manifest lifecycle (validate / apply / diff / rollback), dominio puro
 *    pilotato sia dai servizi reali sia dai comandi `iam:manifest:*`.
 *  - OAuth2/OIDC: firma/verifica JWT ES256 del TokenSigner contro il JWKS, introspection RFC 7662
 *    e rotation/replay-protection dei refresh token (RFC 9700) tramite il repository reale.
 *
 * Nessuna classe IAM è mockata: i test usano i servizi, i comandi e i repository concreti.
 */
class OAuthAndManifestTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        // La generazione della chiave EC P-256 del TokenSigner usa openssl_pkey_new, che su
        // Windows/herd fallisce senza un file di configurazione openssl. Un cnf vuoto è
        // sufficiente per la sola keygen EC: lo scriviamo e lo puntiamo via config IAM, così
        // il singleton LocalTokenSigner lo riceve quando viene risolto (lazy).
        $cnf = sys_get_temp_dir().DIRECTORY_SEPARATOR.'iam-test-openssl.cnf';
        if (! is_file($cnf)) {
            file_put_contents($cnf, "[req]\n");
        }
        config([
            'iam.crypto.openssl_config' => $cnf,
            'iam.tokens.issuer' => 'https://iam.test',
        ]);
    }

    // ---------------------------------------------------------------------
    // Manifest / Application Registry
    // ---------------------------------------------------------------------

    public function test_manifest_validate_accepts_wellformed_and_rejects_malformed(): void
    {
        $validator = app(ManifestValidator::class);

        // Manifest ben formato → valido, nessun errore.
        $ok = $validator->validate($this->validManifest('billing'));
        $this->assertTrue($ok->valid, 'Un manifest ben formato deve validare.');
        $this->assertSame([], $ok->errors);

        // Manifest malformato: slug app non valido, app.name mancante, app.type con typo,
        // e un ruolo che referenzia un permission non dichiarato (dangling reference).
        $bad = $validator->validate([
            'schema' => 'laravel-iam.manifest.v2',
            'app' => ['key' => 'Bad Key!', 'type' => 'servcie'],
            'permissions' => [['key' => 'good.perm', 'risk' => 'low']],
            'roles' => [['key' => 'r1', 'permissions' => ['nonexistent.perm']]],
        ]);
        $this->assertFalse($bad->valid, 'Un manifest malformato non deve validare.');
        $joined = implode("\n", $bad->errors);
        $this->assertStringContainsString('app.key', $joined);
        $this->assertStringContainsString('app.name', $joined);
        $this->assertStringContainsString('app.type', $joined);
        $this->assertStringContainsString('non dichiarato', $joined); // dangling role→permission ref

        // Stessa logica raggiungibile dalla CLI reale `iam:manifest:validate`.
        $this->artisan('iam:manifest:validate', ['file' => $this->writeManifest($this->validManifest('billing'))])
            ->assertExitCode(0);
        $this->artisan('iam:manifest:validate', ['file' => $this->writeManifest([
            'schema' => 'nope',
            'app' => ['key' => 'Bad Key!'],
        ])])->assertExitCode(1);
    }

    public function test_manifest_apply_creates_catalog_and_owns_oauth_client(): void
    {
        $manifest = [
            'schema' => 'laravel-iam.manifest.v2',
            'app' => ['key' => 'shop', 'name' => 'Shop', 'type' => 'laravel', 'risk_level' => 'low'],
            'auth' => ['client_type' => 'confidential', 'redirect_uris' => ['https://shop.test/callback']],
            'permissions' => [
                ['key' => 'orders.view', 'risk' => 'low', 'resource' => 'orders', 'action' => 'view'],
                ['key' => 'orders.manage', 'risk' => 'medium'],
            ],
            'roles' => [
                ['key' => 'manager', 'label' => 'Manager', 'permissions' => ['orders.view', 'orders.manage']],
            ],
        ];

        // --approve: aggiungere redirect_uris su una nuova app è un cambio "sensibile" (gate umano).
        $this->artisan('iam:manifest:apply', ['file' => $this->writeManifest($manifest), '--approve' => true])
            ->assertExitCode(0);

        // Application creata.
        $app = Application::query()->where('key', 'shop')->first();
        $this->assertNotNull($app, 'Application deve esistere dopo apply.');
        $this->assertSame('laravel', $app->type);
        $this->assertNotNull($app->current_manifest_id);

        // Permessi nel catalogo (full_key = app:key).
        $this->assertNotNull(Permission::query()->where('full_key', 'shop:orders.view')->first());
        $manage = Permission::query()->where('full_key', 'shop:orders.manage')->first();
        $this->assertNotNull($manage);
        $this->assertSame('medium', $manage->risk);

        // Ruolo + role_permissions (pivot con 2 permessi).
        $role = Role::query()->where('full_key', 'shop:manager')->first();
        $this->assertNotNull($role);
        $this->assertSame(2, $role->permissions()->count());

        // Il registry possiede l'OAuth client dell'app (client_id = cli_<appKey>).
        $client = OauthClient::query()->where('client_id', 'cli_shop')->first();
        $this->assertNotNull($client, 'Apply deve registrare/possedere un OAuth client.');
        $this->assertSame('shop', $client->application_key);
        $this->assertTrue($client->is_confidential);
        $this->assertTrue($client->is_first_party);
        $this->assertSame(['authorization_code', 'refresh_token'], $client->grants);
        $this->assertSame(['https://shop.test/callback'], $client->redirect_uris);
        // Scope = OIDC standard + chiavi dei permessi dichiarati.
        $this->assertContains('openid', $client->scopes);
        $this->assertContains('orders.view', $client->scopes);
        $this->assertContains('orders.manage', $client->scopes);
    }

    public function test_manifest_diff_reports_added_and_removed_permissions(): void
    {
        $registry = app(ManifestRegistry::class);

        // v1 applicata: permessi [contacts.view, contacts.edit].
        $this->artisan('iam:manifest:apply', [
            'file' => $this->writeManifest($this->crmManifest(['contacts.view', 'contacts.edit'])),
            '--approve' => true,
        ])->assertExitCode(0);

        // v2 sottomessa: edit rimosso, delete aggiunto. submit() valida e calcola il diff vs lo
        // stato applicato (v1) senza applicare nulla.
        $v2 = $registry->submit($this->crmManifest(['contacts.view', 'contacts.delete']));
        $diff = $v2->diff;

        $this->assertIsArray($diff);
        $this->assertContains('contacts.delete', $diff['permissions']['added']);
        $this->assertContains('contacts.edit', $diff['permissions']['removed']);
        $this->assertNotContains('contacts.view', $diff['permissions']['added']);
        $this->assertNotContains('contacts.view', $diff['permissions']['removed']);
        // La rimozione di un permesso è un cambio breaking.
        $this->assertTrue($diff['breaking']);
    }

    public function test_manifest_rollback_restores_previous_applied_state(): void
    {
        // v1: [reports.view, reports.export].
        $this->artisan('iam:manifest:apply', [
            'file' => $this->writeManifest($this->invManifest(['reports.view', 'reports.export'])),
            '--approve' => true,
        ])->assertExitCode(0);

        // v2: export rimosso, delete aggiunto.
        $this->artisan('iam:manifest:apply', [
            'file' => $this->writeManifest($this->invManifest(['reports.view', 'reports.delete'])),
            '--approve' => true,
        ])->assertExitCode(0);

        // Dopo v2: export deprecato (soft), delete attivo.
        $this->assertNotNull(Permission::query()->where('full_key', 'inv:reports.export')->first()->deprecated_at);
        $this->assertNull(Permission::query()->where('full_key', 'inv:reports.delete')->first()->deprecated_at);

        // Rollback alla versione precedente applicata (v1). --approve perché la target conteneva
        // cambi sensibili (requires_approval).
        $this->artisan('iam:manifest:rollback', ['app' => 'inv', '--approve' => true])
            ->assertExitCode(0);

        // Stato tornato a v1: export ri-attivato, delete deprecato.
        $this->assertNull(Permission::query()->where('full_key', 'inv:reports.export')->first()->deprecated_at);
        $this->assertNotNull(Permission::query()->where('full_key', 'inv:reports.delete')->first()->deprecated_at);

        // L'app punta di nuovo al manifest v1.
        $v1 = Manifest::query()->where('application_key', 'inv')->where('version', 1)->first();
        $this->assertSame($v1->id, Application::query()->where('key', 'inv')->first()->current_manifest_id);
    }

    // ---------------------------------------------------------------------
    // OAuth / OIDC
    // ---------------------------------------------------------------------

    public function test_access_token_is_es256_jwt_and_verifies_against_jwks(): void
    {
        $signer = app(TokenSigner::class);

        $jwt = $signer->issue([
            'sub' => 'user-1',
            'client_id' => 'cli_shop',
            'aud' => 'cli_shop',
            'scope' => 'openid profile',
        ], 900);

        // Forma JWT: 3 segmenti, header ES256 con kid.
        $parts = explode('.', $jwt);
        $this->assertCount(3, $parts);
        $header = json_decode($this->b64urlDecode($parts[0]), true);
        $this->assertSame('ES256', $header['alg']);
        $this->assertArrayHasKey('kid', $header);

        // Verifica reale (firma + iss + validità temporale) tramite il signer.
        $claims = $signer->parse($jwt);
        $this->assertSame('user-1', $claims['sub']);
        $this->assertSame('openid profile', $claims['scope']);
        $this->assertSame('https://iam.test', $claims['iss']);

        // Il kid del token è pubblicato nel JWKS come chiave EC P-256 di verifica.
        $jwks = $signer->jwks();
        $this->assertNotEmpty($jwks);
        $kids = array_column($jwks, 'kid');
        $this->assertContains($header['kid'], $kids);
        $jwk = $jwks[array_search($header['kid'], $kids, true)];
        $this->assertSame('EC', $jwk['kty']);
        $this->assertSame('P-256', $jwk['crv']);
        $this->assertSame('ES256', $jwk['alg']);

        // Token manomesso (firma alterata) → la verifica fallisce.
        $sig = $parts[2];
        $tampered = $parts[0].'.'.$parts[1].'.'.($sig[0] === 'a' ? 'b' : 'a').substr($sig, 1);
        $rejected = false;
        try {
            $signer->parse($tampered);
        } catch (\Throwable) {
            $rejected = true;
        }
        $this->assertTrue($rejected, 'Un token con firma manomessa non deve verificare.');
    }

    public function test_introspection_reports_active_revoked_and_expired_tokens(): void
    {
        $signer = app(TokenSigner::class);

        // Resource server: client confidential autenticato che chiama /oauth/introspect.
        OauthClient::query()->create([
            'client_id' => 'cli_rs',
            'name' => 'Resource Server',
            'grants' => ['client_credentials'],
            'scopes' => ['openid'],
            'is_confidential' => true,
            'is_first_party' => true,
        ]);
        // secret non è fillable: lo impostiamo come fa il dominio (hash).
        $rs = OauthClient::query()->where('client_id', 'cli_rs')->first();
        $rs->secret = \Illuminate\Support\Facades\Hash::make('s3cret');
        $rs->save();

        // (a) Token attivo: firmato, presente nel ledger, non revocato.
        $active = $signer->issue(['jti' => 'jti-active', 'sub' => 'cli_rs', 'client_id' => 'cli_rs', 'aud' => 'cli_rs', 'scope' => 'openid'], 900);
        OauthAccessToken::query()->create(['jti' => 'jti-active', 'client_id' => 'cli_rs', 'revoked' => false, 'expires_at' => now()->addHour()]);
        $this->introspect($active)->assertOk()->assertJson(['active' => true, 'client_id' => 'cli_rs', 'scope' => 'openid']);

        // (b) Token revocato nel ledger → inactive (fail-closed).
        $revoked = $signer->issue(['jti' => 'jti-revoked', 'sub' => 'cli_rs', 'client_id' => 'cli_rs', 'aud' => 'cli_rs', 'scope' => 'openid'], 900);
        OauthAccessToken::query()->create(['jti' => 'jti-revoked', 'client_id' => 'cli_rs', 'revoked' => true, 'expires_at' => now()->addHour()]);
        $this->introspect($revoked)->assertOk()->assertJson(['active' => false]);

        // (c) Token sconosciuto al ledger → inactive.
        $unknown = $signer->issue(['jti' => 'jti-unknown', 'sub' => 'cli_rs', 'client_id' => 'cli_rs', 'aud' => 'cli_rs', 'scope' => 'openid'], 900);
        $this->introspect($unknown)->assertOk()->assertJson(['active' => false]);

        // (d) Token scaduto: stesso setup del caso attivo (ledger presente, non revocato), ma exp
        // nel passato → il signer rifiuta la firma temporalmente non valida → inactive.
        $expiring = $signer->issue(['jti' => 'jti-exp', 'sub' => 'cli_rs', 'client_id' => 'cli_rs', 'aud' => 'cli_rs', 'scope' => 'openid'], 1);
        OauthAccessToken::query()->create(['jti' => 'jti-exp', 'client_id' => 'cli_rs', 'revoked' => false, 'expires_at' => now()->addHour()]);
        sleep(2); // attende il superamento dell'exp (ttl=1s, nessun leeway)
        $this->introspect($expiring)->assertOk()->assertJson(['active' => false]);
    }

    public function test_refresh_token_rotation_and_replay_protection(): void
    {
        /** @var RefreshTokenRepository $repo */
        $repo = app(RefreshTokenRepository::class);

        // Ledger degli access token associati ai refresh (la revoca della catena li propaga).
        OauthAccessToken::query()->create(['jti' => 'at-A', 'client_id' => 'cli_shop', 'revoked' => false, 'expires_at' => now()->addHour()]);
        OauthAccessToken::query()->create(['jti' => 'at-B', 'client_id' => 'cli_shop', 'revoked' => false, 'expires_at' => now()->addHour()]);

        // Token A apre una nuova catena (chain_id = id di A).
        $repo->persistNewRefreshToken($this->refreshEntity('rt-A', 'at-A'));
        $chainId = OauthRefreshToken::query()->where('refresh_token_id', 'rt-A')->value('chain_id');
        $this->assertSame('rt-A', $chainId);

        // --- Rotazione di A (stessa sequenza di IamRefreshTokenGrant::validateOldRefreshToken) ---
        $this->assertFalse($repo->isRefreshTokenRevoked('rt-A'));
        $this->assertTrue($repo->claimForRotation('rt-A'), 'Il primo uso di A deve vincere il claim atomico.');
        $repo->continueChain('rt-A');
        $repo->persistNewRefreshToken($this->refreshEntity('rt-B', 'at-B'));

        // A è ora revocato; B vive nella STESSA catena ed è usabile.
        $this->assertTrue(OauthRefreshToken::query()->where('refresh_token_id', 'rt-A')->value('revoked'));
        $this->assertSame('rt-A', OauthRefreshToken::query()->where('refresh_token_id', 'rt-B')->value('chain_id'));
        $this->assertFalse($repo->isRefreshTokenRevoked('rt-B'));

        // --- Replay: A (già ruotato/revocato) viene ripresentato ---
        $this->assertTrue($repo->isRefreshTokenRevoked('rt-A'), 'Un refresh token già ruotato è rilevato come revocato.');
        $repo->revokeChain('rt-A'); // ciò che fa il grant alla rilevazione del replay

        // L'intera catena è compromessa: B e i relativi access token sono revocati (RFC 9700).
        $this->assertTrue(OauthTokenChain::query()->whereKey('rt-A')->value('compromised'));
        $this->assertTrue($repo->isRefreshTokenRevoked('rt-B'), 'Il replay di A invalida anche B (stessa catena).');
        $this->assertTrue(OauthRefreshToken::query()->where('refresh_token_id', 'rt-B')->value('revoked'));
        $this->assertTrue(OauthAccessToken::query()->where('jti', 'at-B')->value('revoked'));
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** @param array<string, mixed> $payload */
    private function writeManifest(array $payload): string
    {
        $path = sys_get_temp_dir().DIRECTORY_SEPARATOR.'iam-manifest-'.uniqid().'.json';
        file_put_contents($path, json_encode($payload, JSON_THROW_ON_ERROR));

        return $path;
    }

    /** @return array<string, mixed> */
    private function validManifest(string $key): array
    {
        return [
            'schema' => 'laravel-iam.manifest.v2',
            'app' => ['key' => $key, 'name' => ucfirst($key), 'type' => 'service', 'risk_level' => 'low'],
            'auth' => ['client_type' => 'confidential'],
            'permissions' => [
                ['key' => 'invoices.view', 'risk' => 'low', 'resource' => 'invoices', 'action' => 'view'],
                ['key' => 'invoices.create', 'risk' => 'low'],
            ],
            'roles' => [
                ['key' => 'clerk', 'label' => 'Clerk', 'permissions' => ['invoices.view']],
            ],
        ];
    }

    /**
     * @param  list<string>  $permissionKeys
     * @return array<string, mixed>
     */
    private function crmManifest(array $permissionKeys): array
    {
        return $this->appManifest('crm', $permissionKeys);
    }

    /**
     * @param  list<string>  $permissionKeys
     * @return array<string, mixed>
     */
    private function invManifest(array $permissionKeys): array
    {
        return $this->appManifest('inv', $permissionKeys);
    }

    /**
     * @param  list<string>  $permissionKeys
     * @return array<string, mixed>
     */
    private function appManifest(string $key, array $permissionKeys): array
    {
        return [
            'schema' => 'laravel-iam.manifest.v2',
            'app' => ['key' => $key, 'name' => strtoupper($key), 'type' => 'service', 'risk_level' => 'low'],
            'auth' => ['client_type' => 'confidential'],
            'permissions' => array_map(static fn (string $k): array => ['key' => $k, 'risk' => 'low'], $permissionKeys),
            'roles' => [],
        ];
    }

    /** Costruisce un refresh token entity reale (league) per il repository IAM. */
    private function refreshEntity(string $id, string $accessJti): RefreshTokenEntity
    {
        $access = new AccessTokenEntity(app(TokenSigner::class), app(AccessTokenClaims::class));
        $access->setIdentifier($accessJti);

        $rt = new RefreshTokenEntity;
        $rt->setIdentifier($id);
        $rt->setExpiryDateTime(new \DateTimeImmutable('+14 days'));
        $rt->setAccessToken($access);

        return $rt;
    }

    private function introspect(string $token): \Illuminate\Testing\TestResponse
    {
        // Credenziali del resource server nel body (equivalente all'HTTP Basic per ClientAuthenticator).
        return $this->postJson('/oauth/introspect', [
            'token' => $token,
            'client_id' => 'cli_rs',
            'client_secret' => 's3cret',
        ]);
    }

    private function b64urlDecode(string $value): string
    {
        return base64_decode(strtr($value, '-_', '+/'));
    }
}
