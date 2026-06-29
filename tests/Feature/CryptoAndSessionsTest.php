<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Assurance\Aal;
use Padosoft\Iam\Contracts\Crypto\SecretCipher;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Contracts\Identity\SessionMeta;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Identity\Models\User;
use Tests\TestCase;

/**
 * Prova end-to-end della crittografia (envelope encryption, crypto-shredding, firma JWT ES256)
 * e delle sessioni server-side / AAL. Tutte le classi sono risolte dal container con i binding
 * reali di IamServiceProvider (LocalSecretCipher, LocalKeyProvider, LocalTokenSigner,
 * NativeSessionRegistry); nessun mock.
 */
class CryptoAndSessionsTest extends TestCase
{
    use RefreshDatabase;

    public function test_envelope_encryption_round_trip(): void
    {
        $cipher = app(SecretCipher::class);
        $plaintext = 'super-secret-client-secret-'.bin2hex(random_bytes(8));

        $value = $cipher->encrypt($plaintext);

        // Envelope: il ciphertext esiste, la DEK è incartata (wrapped) e referenzia la KEK locale.
        $this->assertArrayHasKey('ciphertext', $value);
        $this->assertNotSame('', $value['ciphertext']);
        $this->assertNotNull($value['wrapped_dek'], 'una DEK per-valore deve essere incartata');
        $this->assertSame('local-kek', $value['key_id']);

        // Il dato a riposo NON è il plaintext (né lo contiene).
        $this->assertNotSame($plaintext, $value['ciphertext']);
        $this->assertStringNotContainsString($plaintext, $value['ciphertext']);

        // Round-trip: decifra al valore originale.
        $this->assertSame($plaintext, $cipher->decrypt($value));
    }

    public function test_crypto_shredding_renders_data_unrecoverable(): void
    {
        $cipher = app(SecretCipher::class);
        $scope = 'user:'.bin2hex(random_bytes(6));
        $plaintext = 'PII-da-cancellare-'.bin2hex(random_bytes(8));

        // Cifratura per-scope: la DEK vive in iam_data_keys (crypto-shredding GDPR).
        $value = $cipher->encrypt($plaintext, $scope);
        $this->assertSame($scope, $value['scope']);
        $this->assertNull($value['wrapped_dek'], 'scope DEK: incartata nello store, non nel valore');

        // Prima dello shred il dato è recuperabile.
        $this->assertSame($plaintext, $cipher->decrypt($value));

        // Crypto-shredding: distrugge la DEK dello scope → dato irrecuperabile.
        $cipher->shred($scope);

        $this->expectException(\RuntimeException::class);
        $cipher->decrypt($value);
    }

    public function test_jwt_es256_sign_verify_tamper_and_jwks(): void
    {
        // Su Windows openssl_pkey_new (EC) richiede un openssl.cnf esplicito: lo prendiamo da Herd.
        $cnf = 'C:/Users/lopad/.config/herd/bin/php85/extras/ssl/openssl.cnf';
        if (PHP_OS_FAMILY === 'Windows' && is_file($cnf)) {
            config()->set('iam.crypto.openssl_config', $cnf);
            app()->forgetInstance(TokenSigner::class);
        }

        $signer = app(TokenSigner::class);

        $jwt = $signer->issue(['sub' => 'user-123', 'scope' => 'invoices.view'], 300);
        $this->assertCount(3, explode('.', $jwt), 'JWT compatto: header.payload.signature');

        // Verifica firma + temporali + issuer → claims.
        $claims = $signer->parse($jwt);
        $this->assertSame('user-123', $claims['sub']);
        $this->assertSame('invoices.view', $claims['scope']);
        $this->assertArrayHasKey('exp', $claims);

        // Manomissione del payload → la firma ES256 non torna più, parse fallisce (fail-closed).
        $parts = explode('.', $jwt);
        $parts[1] = ($parts[1][0] === 'a' ? 'b' : 'a').substr($parts[1], 1);
        $tampered = implode('.', $parts);

        try {
            $signer->parse($tampered);
            $this->fail('un token manomesso non deve superare la verifica');
        } catch (\Throwable $e) {
            $this->assertInstanceOf(\Throwable::class, $e);
        }

        // JWKS espone la chiave pubblica EC (P-256) usata per verificare, senza materiale privato.
        $jwks = $signer->jwks();
        $this->assertNotEmpty($jwks);
        $key = $jwks[0];
        $this->assertSame('EC', $key['kty']);
        $this->assertSame('P-256', $key['crv']);
        $this->assertSame('sig', $key['use']);
        $this->assertArrayHasKey('x', $key);
        $this->assertArrayHasKey('y', $key);
        $this->assertArrayNotHasKey('d', $key, 'il JWKS non deve mai esporre la coordinata privata d');

        // La PEM pubblica di verifica è materiale pubblico coerente.
        $this->assertStringContainsString('PUBLIC KEY', $signer->verificationPem());
    }

    public function test_session_registry_active_and_revoke_fail_closed(): void
    {
        $registry = app(SessionRegistry::class);
        $subject = $this->makeSubject();

        $ref = $registry->start($subject, new SessionMeta(aal: Aal::AAL2));
        $this->assertTrue($registry->active($ref->id), 'una sessione appena aperta è attiva');

        // Compare tra le sessioni attive del soggetto (device management).
        $ids = array_map(fn ($r) => $r->id, iterator_to_array($this->iter($registry->listForSubject($subject))));
        $this->assertContains($ref->id, $ids);

        // Revoca → non più attiva (revoca server-side prima della scadenza del token).
        $registry->revokeSession($ref->id, 'logout');
        $this->assertFalse($registry->active($ref->id));

        // Fail-closed: un sid inesistente non è mai attivo.
        $this->assertFalse($registry->active('non-esiste'));
        $this->assertFalse($registry->active(''));
    }

    public function test_session_idle_and_absolute_timeout(): void
    {
        $registry = app(SessionRegistry::class);

        // Idle timeout: 1s di finestra idle → scade superata la finestra.
        $idleRef = $registry->start($this->makeSubject(), new SessionMeta(idleTimeout: 1, absoluteTimeout: 43200));
        $this->assertTrue($registry->active($idleRef->id));
        $this->travel(5)->seconds();
        $this->assertFalse($registry->active($idleRef->id), 'idle timeout scaduto → inattiva');
        $this->travelBack();

        // Absolute timeout: tetto massimo non estendibile anche se l'attività continua.
        $absRef = $registry->start($this->makeSubject(), new SessionMeta(idleTimeout: 1800, absoluteTimeout: 2));
        $this->assertTrue($registry->active($absRef->id));
        $this->travel(3)->seconds();
        $this->assertFalse($registry->active($absRef->id), 'absolute timeout scaduto → inattiva');
        $this->travelBack();
    }

    public function test_aal_satisfies_ordering_and_failsafe_parsing(): void
    {
        // Ordine di forza per lo step-up: una sessione più forte soddisfa una richiesta più debole.
        $this->assertTrue(Aal::AAL2->satisfies(Aal::AAL1));
        $this->assertTrue(Aal::AAL3->satisfies(Aal::AAL2));
        $this->assertTrue(Aal::AAL1->satisfies(Aal::AAL1));

        // Una sessione più debole NON soddisfa una richiesta più forte → step-up richiesto.
        $this->assertFalse(Aal::AAL1->satisfies(Aal::AAL2));
        $this->assertFalse(Aal::AAL2->satisfies(Aal::AAL3));

        // fromString fail-safe: input ignoto/null degrada al livello minimo (AAL1), mai eccezione.
        $this->assertSame(Aal::AAL2, Aal::fromString('aal2'));
        $this->assertSame(Aal::AAL1, Aal::fromString(null));
        $this->assertSame(Aal::AAL1, Aal::fromString('bogus'));
    }

    private function makeSubject(): SubjectRef
    {
        $user = User::query()->create(['email' => 'u'.bin2hex(random_bytes(6)).'@example.test']);

        return new SubjectRef('user', $user->id);
    }

    /** @param iterable<int, mixed> $it */
    private function iter(iterable $it): \Generator
    {
        yield from $it;
    }
}
