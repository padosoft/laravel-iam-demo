<?php

declare(strict_types=1);

namespace Tests\Feature;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Schema;
use Padosoft\Iam\Ai\AdvisoryClient;
use Padosoft\Iam\Ai\Contracts\AiProvider;
use Padosoft\Iam\Ai\Governance\HallucinationGuard;
use Padosoft\Iam\Ai\Governance\Redactor;
use Padosoft\Iam\Ai\Modules\AccessExplainer;
use Padosoft\Iam\Ai\Providers\DisabledProvider;
use Padosoft\Iam\Bridge\Spatie\Migration\ManifestGenerator;
use Padosoft\Iam\Bridge\Spatie\Migration\PermissionMapper;
use Padosoft\Iam\Bridge\Spatie\Migration\SpatieScanner;
use Padosoft\Iam\Bridge\Spatie\Shadow\RecordsMismatch;
use Padosoft\Iam\Bridge\Spatie\Shadow\ShadowGate;
use Padosoft\Iam\Client\Deciders\HttpDecider;
use Padosoft\Iam\Client\Deciders\LocalDecider;
use Padosoft\Iam\Client\DecisionRequest;
use Padosoft\Iam\Client\IamClient;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Spatie\Permission\Models\Permission as SpatiePermission;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\Traits\HasRoles;
use Tests\TestCase;

/**
 * Prova end-to-end dei tre package opzionali: governance/advisory AI (sempre advisory, spenta di
 * default), client SDK (deciders tutti fail-closed + Gate adapter) e bridge di migrazione Spatie
 * (inventory read-only, manifest, shadow-diff). Niente infra esterna: si esercitano i percorsi
 * deterministici/disabilitati e i transport con handler finti.
 */
class AiClientBridgeTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        // La cache delle decisioni (array store) è in-process e sopravvive tra i test: la azzero per
        // non far trapelare un esito cachato in un'asserzione successiva.
        $this->app->make('cache')->store('array')->clear();
    }

    // ----------------------------------------------------------------------------- AI: governance --

    /** 1. Il Redactor elimina segreti/PII PRIMA che il testo possa lasciare il perimetro. */
    public function test_redactor_strips_secrets_and_pii_before_leaving(): void
    {
        $redactor = new Redactor;
        // NB: la regola `password=...` consuma fino a fine riga, quindi l'IP va prima per non venirne
        // inglobato — così si verifica davvero il suo placeholder dedicato.
        $text = 'Contatta admin@example.com dal nodo 10.0.0.42 con header Authorization: '
            .'Bearer abc123TOKENxyz e usa password=hunter2';

        $out = $redactor->redact($text);

        $this->assertTrue($redactor->didRedact, 'il redactor deve segnalare di aver redatto qualcosa');
        $this->assertStringNotContainsString('admin@example.com', $out);
        $this->assertStringNotContainsString('hunter2', $out);
        $this->assertStringNotContainsString('abc123TOKENxyz', $out);
        $this->assertStringNotContainsString('10.0.0.42', $out);
        $this->assertStringContainsString('[REDACTED_EMAIL]', $out);
        $this->assertStringContainsString('[REDACTED_AUTH]', $out);
        $this->assertStringContainsString('[REDACTED]', $out); // password=[REDACTED]
        $this->assertStringContainsString('[REDACTED_IP]', $out);
    }

    /** 2. L'hallucination-guard tiene gli ID presenti nelle evidenze e segnala quelli inventati. */
    public function test_hallucination_guard_keeps_whitelisted_ids_and_flags_invented_ones(): void
    {
        $guard = new HallucinationGuard;
        $allowed = ['dec_0123456789ab'];

        $dirty = 'Decisione dec_0123456789ab supportata da grn_deadbeefcafe9999.';
        $violations = $guard->violations($dirty, $allowed);

        $this->assertContains('grn_deadbeefcafe9999', $violations, 'un ID inventato è una violazione');
        $this->assertNotContains('dec_0123456789ab', $violations, "l'ID reale non è una violazione");
        $this->assertFalse($guard->passes($dirty, $allowed));

        // Output che cita solo evidenze reali → nessuna violazione.
        $clean = 'Accesso motivato dalla decisione dec_0123456789ab.';
        $this->assertSame([], $guard->violations($clean, $allowed));
        $this->assertTrue($guard->passes($clean, $allowed));
    }

    /** 3. AccessExplainer è fail-closed: non fabbrica mai un "CONSENTITO" su una decisione negata. */
    public function test_access_explainer_is_fail_closed_on_denied_decisions(): void
    {
        $explainer = $this->app->make(AccessExplainer::class);

        $denied = $explainer->explain([
            'allowed' => false,
            'decision_id' => 'dec_0123456789ab',
            'explanation' => ['nessun grant corrispondente'],
            'matched' => [],
        ]);
        $this->assertStringContainsString('NEGATO', $denied->text);
        $this->assertStringNotContainsString('CONSENTITO', $denied->text);
        $this->assertContains('dec_0123456789ab', $denied->citations);

        // Fail-closed: un `allowed` truthy ma non === true (qui la stringa "false") resta NEGATO.
        $spurious = $explainer->explain(['allowed' => 'false', 'decision_id' => 'dec_0123456789ab']);
        $this->assertStringContainsString('NEGATO', $spurious->text);
        $this->assertStringNotContainsString('CONSENTITO', $spurious->text);

        // Solo un boolean true vero produce una spiegazione di consenso.
        $allowedAdvisory = $explainer->explain([
            'allowed' => true,
            'decision_id' => 'dec_0123456789ab',
            'explanation' => ['grant diretto'],
            'matched' => [['key' => 'role:admin']],
        ]);
        $this->assertStringContainsString('CONSENTITO', $allowedAdvisory->text);
    }

    /** 4. Modulo AI spento di default: percorso advisory deterministico, nessuna chiamata esterna. */
    public function test_ai_disabled_by_default_returns_deterministic_fallback(): void
    {
        $this->assertFalse((bool) config('iam-ai.enabled'), 'l\'AI deve essere spenta out-of-the-box');
        $this->assertInstanceOf(DisabledProvider::class, $this->app->make(AiProvider::class));

        // Il provider disabilitato lancia se invocato: garantisce che nessun transport sia cablato.
        $this->expectExceptionThrownByDisabledProvider();

        $client = $this->app->make(AdvisoryClient::class);
        $advisory = $client->advise(
            task: 'unit_probe',
            system: 'system',
            userPrompt: 'spiega',
            evidence: ['decision_id' => 'dec_0123456789ab'],
            allowedRefs: ['dec_0123456789ab'],
            deterministicFallback: 'Risposta deterministica dai tool.',
        );

        $this->assertFalse($advisory->aiUsed, 'AI spenta → nessun uso del modello');
        $this->assertTrue($advisory->guardPassed);
        $this->assertSame('deterministic', $advisory->provider);
        $this->assertSame('Risposta deterministica dai tool.', $advisory->text);
    }

    private function expectExceptionThrownByDisabledProvider(): void
    {
        // Verifica diretta (separata dall'advise, che NON deve propagare): DisabledProvider::complete lancia.
        try {
            (new DisabledProvider)->complete('s', 'u');
            $this->fail('DisabledProvider::complete avrebbe dovuto lanciare');
        } catch (\RuntimeException $e) {
            $this->assertStringContainsString('AI disabilitata', $e->getMessage());
        }
    }

    // ----------------------------------------------------------------------------- Client SDK ------

    /** 5. LocalDecider avvolge il PDP in-process: nega di default, consente dopo un grant. */
    public function test_local_decider_is_fail_closed_then_allows_after_grant(): void
    {
        $decider = new LocalDecider($this->app->make(AuthorizationEngine::class));
        $request = new DecisionRequest(permission: 'invoices.view', subjectId: '77', subjectType: 'user');

        $deny = $decider->decide($request);
        $this->assertFalse($deny->allowed, 'senza grant → deny (fail-closed)');
        $this->assertFalse($deny->granted());

        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => '77',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices.view',
            'effect' => 'permit', 'valid_from' => now(),
        ]);

        $allow = $decider->decide($request);
        $this->assertTrue($allow->allowed, 'grant permit → allow');
        $this->assertTrue($allow->granted());
    }

    /** 6. Un errore di trasporto/parse su un decider → DENY, mai allow (nessun opt-out fail-open). */
    public function test_http_decider_fails_closed_on_transport_and_parse_errors(): void
    {
        $request = new DecisionRequest(permission: 'invoices.view', subjectId: '1', subjectType: 'user');

        // (a) HTTP non-2xx → deny.
        $http500 = new HttpDecider($this->guzzleReturning(new Response(503)), 'https://iam.test', 'tok');
        $d = $http500->decide($request);
        $this->assertFalse($d->allowed);
        $this->assertContains('http 503', $d->explanation);

        // (b) Body 2xx ma non-JSON → deny (parse error).
        $badBody = new HttpDecider($this->guzzleReturning(new Response(200, [], '<<<not json>>>')), 'https://iam.test', null);
        $d = $badBody->decide($request);
        $this->assertFalse($d->allowed);
        $this->assertContains('invalid body', $d->explanation);

        // (c) Eccezione di trasporto (connessione) → deny, mai un'eccezione propagata.
        $boom = new HttpDecider($this->guzzleReturning(new \RuntimeException('connection refused')), 'https://iam.test', null);
        $d = $boom->decide($request);
        $this->assertFalse($d->allowed);
        $this->assertFalse($d->granted());
    }

    private function guzzleReturning(Response|\Throwable $result): GuzzleClient
    {
        return new GuzzleClient(['handler' => HandlerStack::create(new MockHandler([$result]))]);
    }

    /** 7. Gate adapter: una volta bindato, il Gate Laravel consente/nega coerentemente col PDP. */
    public function test_gate_adapter_matches_pdp_for_namespaced_abilities(): void
    {
        $user = $this->makeUser(501);

        // Grant solo per la permission "view"; "delete" resta priva di grant.
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => '501',
            'privilege_type' => 'permission', 'privilege_key' => 'warehouse:stock.view',
            'effect' => 'permit', 'valid_from' => now(),
        ]);

        $gateAllowsView = Gate::forUser($user)->allows('warehouse:stock.view');
        $gateAllowsDelete = Gate::forUser($user)->allows('warehouse:stock.delete');

        $this->assertTrue($gateAllowsView, 'ability concessa dal PDP → Gate consente');
        $this->assertFalse($gateAllowsDelete, 'ability senza grant → Gate nega (fail-closed)');

        // Coerenza esplicita Gate ↔ PDP (client).
        $client = $this->app->make(IamClient::class);
        $this->assertSame($client->can($user, 'warehouse:stock.view'), $gateAllowsView);
        $this->assertSame($client->can($user, 'warehouse:stock.delete'), $gateAllowsDelete);
    }

    // ----------------------------------------------------------------------------- Bridge Spatie ---

    /** 8. SpatieScanner inventaria roli/permessi esistenti in sola lettura (non muta le tabelle). */
    public function test_spatie_scanner_inventories_read_only(): void
    {
        $this->setUpSpatieTables();
        $this->seedSpatieFixture();

        $before = $this->spatieRowCounts();

        $scan = $this->app->make(SpatieScanner::class)->scan();

        // Inventory corretto.
        $this->assertCount(2, $scan['permissions']);
        $this->assertSame(['web'], $scan['guards']);
        $this->assertSame(1, $scan['model_has_roles_count']);

        $manager = collect($scan['roles'])->firstWhere('name', 'manager');
        $this->assertNotNull($manager);
        $this->assertEqualsCanonicalizing(['orders.view', 'orders.refund'], $manager['permissions']);

        $direct = collect($scan['direct_user_permissions'])->pluck('permission')->all();
        $this->assertContains('orders.refund', $direct);

        // Read-only: nessuna tabella Spatie è stata mutata dallo scan.
        $this->assertSame($before, $this->spatieRowCounts(), 'lo scan non deve mutare le tabelle Spatie');
    }

    /** 9. ManifestGenerator produce un manifest IAM valido dall'inventory scansionato. */
    public function test_manifest_generator_produces_valid_iam_manifest(): void
    {
        $this->setUpSpatieTables();
        $this->seedSpatieFixture();

        $scan = $this->app->make(SpatieScanner::class)->scan();
        $manifest = $this->app->make(ManifestGenerator::class)->generate($scan, [
            'key' => 'legacy-app', 'name' => 'Legacy App',
        ]);

        $this->assertSame('laravel-iam.manifest.v2', $manifest['schema']);
        $this->assertSame('legacy-app', $manifest['app']['key']);

        // Tutte le chiavi rispettano lo slug del manifest IAM (^[a-z][a-z0-9_.-]*$).
        foreach ($manifest['permissions'] as $perm) {
            $this->assertMatchesRegularExpression('/^[a-z][a-z0-9_.-]*$/', $perm['key']);
        }

        $refund = collect($manifest['permissions'])->firstWhere('key', 'orders.refund');
        $this->assertNotNull($refund, 'la permission Spatie deve comparire nel manifest');
        $this->assertSame('high', $refund['risk'], 'refund è azione ad alto rischio (euristica)');

        $manager = collect($manifest['roles'])->firstWhere('key', 'manager');
        $this->assertNotNull($manager);
        $this->assertContains('orders.refund', $manager['permissions']);
    }

    /** 10. ShadowGate registra un mismatch quando IAM e Spatie divergono (senza alterare il Gate). */
    public function test_shadow_gate_records_mismatch_without_changing_behavior(): void
    {
        $this->setUpSpatieTables();

        SpatiePermission::create(['name' => 'reports.view', 'guard_name' => 'web']);
        $this->app->make(PermissionRegistrar::class)->forgetCachedPermissions();

        $user = SpatieUserStub::query()->create([
            'name' => 'shadow', 'email' => 'shadow@example.com', 'password' => 'x',
        ]);
        $user->givePermissionTo('reports.view');

        // Spatie consente (probe diretto hasPermissionTo); IAM nega (nessun grant) → divergenza.
        $this->assertTrue($user->hasPermissionTo('reports.view'));
        $this->assertFalse($this->app->make(IamClient::class)->can($user, 'app:reports.view'));

        $recorder = new CapturingRecorder;
        $shadow = new ShadowGate(
            $this->app->make(IamClient::class),
            $recorder,
            $this->app->make(PermissionMapper::class),
            'app',
        );

        $shadow->compare($user, 'reports.view', true, []);

        $this->assertCount(1, $recorder->records, 'la divergenza deve essere registrata');
        $mismatch = $recorder->records[0];
        $this->assertSame((string) $user->getAuthIdentifier(), $mismatch['subjectId']);
        $this->assertSame('reports.view', $mismatch['ability']);
        $this->assertTrue($mismatch['spatieAllows']);
        $this->assertFalse($mismatch['iamAllows']);

        // Shadow non cambia mai l'esito locale del Gate: register() usa Gate::after → null.
        Gate::define('demo.shadow', static fn (): bool => true);
        $shadow->register($this->app->make(\Illuminate\Contracts\Auth\Access\Gate::class));
        $this->assertTrue(Gate::forUser($user)->allows('demo.shadow'), 'lo shadow non altera il risultato locale');
    }

    // --------------------------------------------------------------------------------- helpers -----

    private function makeUser(int $id): Authenticatable
    {
        return PlainUserStub::query()->create([
            'id' => $id, 'name' => 'u'.$id, 'email' => "u{$id}@example.com", 'password' => 'x',
        ]);
    }

    private function setUpSpatieTables(): void
    {
        if (Schema::hasTable('permissions')) {
            return;
        }
        $stub = base_path('vendor/spatie/laravel-permission/database/migrations/create_permission_tables.php.stub');
        (require $stub)->up();
    }

    private function seedSpatieFixture(): void
    {
        DB::table('permissions')->insert([
            ['id' => 1, 'name' => 'orders.view', 'guard_name' => 'web'],
            ['id' => 2, 'name' => 'orders.refund', 'guard_name' => 'web'],
        ]);
        DB::table('roles')->insert([['id' => 1, 'name' => 'manager', 'guard_name' => 'web']]);
        DB::table('role_has_permissions')->insert([
            ['permission_id' => 1, 'role_id' => 1],
            ['permission_id' => 2, 'role_id' => 1],
        ]);
        DB::table('model_has_roles')->insert([
            ['role_id' => 1, 'model_type' => 'App\\Models\\User', 'model_id' => 1],
        ]);
        DB::table('model_has_permissions')->insert([
            ['permission_id' => 2, 'model_type' => 'App\\Models\\User', 'model_id' => 1],
        ]);
    }

    /** @return array<string, int> */
    private function spatieRowCounts(): array
    {
        $tables = ['permissions', 'roles', 'role_has_permissions', 'model_has_roles', 'model_has_permissions'];
        $counts = [];
        foreach ($tables as $table) {
            $counts[$table] = DB::table($table)->count();
        }

        return $counts;
    }
}

/** Sink dei mismatch shadow per il test: cattura invece di loggare (estensione documentata di RecordsMismatch). */
final class CapturingRecorder implements RecordsMismatch
{
    /** @var list<array<string, mixed>> */
    public array $records = [];

    public function record(string $subjectId, string $ability, bool $spatieAllows, bool $iamAllows): void
    {
        $this->records[] = compact('subjectId', 'ability', 'spatieAllows', 'iamAllows');
    }
}

/** Utente Laravel "nudo" (senza trait Spatie) per i test di Gate/PDP. */
final class PlainUserStub extends Authenticatable
{
    protected $table = 'users';

    protected $guarded = [];

    public $timestamps = false;
}

/** Utente con il trait Spatie HasRoles per esercitare il probe hasPermissionTo dello ShadowGate. */
final class SpatieUserStub extends Authenticatable
{
    use HasRoles;

    protected $table = 'users';

    protected $guarded = [];

    public $timestamps = false;

    protected $guard_name = 'web';
}
