<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Padosoft\Iam\Domain\Audit\AuditChainVerifier;
use Padosoft\Iam\Domain\Audit\AuditCheckpointer;
use Padosoft\Iam\Domain\Audit\AuditHasher;
use Padosoft\Iam\Domain\Audit\Export\AuditExporter;
use Padosoft\Iam\Domain\Audit\Models\AuditCheckpoint;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Audit\Models\AuditHead;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Tests\TestCase;

/**
 * Prova che l'audit di Laravel IAM è tamper-evident (hash-chain), verificabile ed esportabile
 * verso SIEM. Tutto passa per i servizi reali (recorder/appender, verifier, checkpointer, exporter)
 * e per i comandi artisan `iam:audit:*`; nessun mock delle classi IAM.
 */
class AuditTest extends TestCase
{
    use RefreshDatabase;

    private const STREAM = 'org-acme';

    /** Registra N eventi reali nello stream via l'AuditRecorder (che li sigilla nella hash-chain). */
    private function recordEvents(): array
    {
        $recorder = app(AuditRecorder::class);

        $e1 = $recorder->record(['stream' => self::STREAM, 'event_type' => 'grant.assigned', 'actor_user_id' => 'u1', 'target_type' => 'permission', 'target_id' => 'invoices.view', 'after_json' => ['effect' => 'permit']]);
        $e2 = $recorder->record(['stream' => self::STREAM, 'event_type' => 'policy.approved', 'actor_user_id' => 'u2', 'target_type' => 'policy', 'target_id' => 'pol-42', 'risk_level' => 'high']);
        $e3 = $recorder->record(['stream' => self::STREAM, 'event_type' => 'grant.revoked', 'actor_user_id' => 'u1', 'target_type' => 'permission', 'target_id' => 'invoices.view']);

        return [$e1, $e2, $e3];
    }

    public function test_append_links_each_event_into_a_hash_chain(): void
    {
        [$e1, $e2, $e3] = $this->recordEvents();

        // Sequenza progressiva e contigua per stream.
        $this->assertSame(1, $e1->seq);
        $this->assertSame(2, $e2->seq);
        $this->assertSame(3, $e3->seq);

        // Il primo evento aggancia il genesi; ogni successivo aggancia l'hash del precedente.
        $this->assertSame(AuditHasher::GENESIS, $e1->prev_hash);
        $this->assertSame($e1->hash, $e2->prev_hash);
        $this->assertSame($e2->hash, $e3->prev_hash);

        // Gli hash sono SHA-256 (64 hex) e distinti.
        foreach ([$e1, $e2, $e3] as $e) {
            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $e->hash);
        }
        $this->assertNotSame($e1->hash, $e2->hash);

        // La testa dello stream punta all'ultimo evento sigillato.
        $head = AuditHead::query()->find(self::STREAM);
        $this->assertSame(3, $head->seq);
        $this->assertSame($e3->hash, $head->hash);
    }

    public function test_verify_passes_on_an_untampered_stream(): void
    {
        $this->recordEvents();

        $result = app(AuditChainVerifier::class)->verify(self::STREAM);

        $this->assertTrue($result->valid, 'una catena non manomessa deve risultare integra');
        $this->assertSame(3, $result->checked);
        $this->assertNull($result->firstBrokenUuid);

        // Lo stesso esito via il comando artisan reale.
        $this->artisan('iam:audit:verify', ['--stream' => self::STREAM])
            ->expectsOutputToContain('OK')
            ->assertExitCode(0);
    }

    public function test_tampering_a_stored_event_breaks_the_chain(): void
    {
        [, $e2] = $this->recordEvents();

        // Manomissione diretta della riga (bypassando l'appender): cambio la decisione registrata.
        // event_type entra nel payload canonico → l'hash ricalcolato non combacerà più.
        DB::table('iam_audit_events')->where('uuid', $e2->uuid)->update(['event_type' => 'policy.rejected']);

        $result = app(AuditChainVerifier::class)->verify(self::STREAM);

        $this->assertFalse($result->valid, 'la verifica deve rilevare la manomissione');
        $this->assertSame($e2->uuid, $result->firstBrokenUuid, 'il primo punto di rottura è la riga manomessa');
        $this->assertStringContainsString('ricalcolato', (string) $result->reason);
        $this->assertSame(2, $result->checked, 'la rottura è rilevata al secondo evento');

        // Il comando artisan reale esce in errore e nomina la rottura.
        $this->artisan('iam:audit:verify', ['--stream' => self::STREAM])
            ->expectsOutputToContain('ROTTURA RILEVATA')
            ->assertExitCode(1);
    }

    public function test_checkpoint_signs_and_stores_the_chain_head(): void
    {
        // Il checkpoint firma la testa con il TokenSigner ES256 (firma reale, niente fake).
        // Su Linux/macOS openssl_pkey_new (EC) usa l'openssl.cnf di sistema e funziona da solo.
        // Solo su Windows (build Herd) serve puntare esplicitamente al cnf accanto al binario PHP,
        // via la config supportata `iam.crypto.openssl_config`.
        if (PHP_OS_FAMILY === 'Windows') {
            $cnf = dirname(PHP_BINARY).DIRECTORY_SEPARATOR.'extras'.DIRECTORY_SEPARATOR.'ssl'.DIRECTORY_SEPARATOR.'openssl.cnf';
            if (! is_file($cnf)) {
                $this->markTestSkipped("openssl.cnf non trovato accanto al binario PHP ({$cnf}); ES256 key-gen non configurabile in questo ambiente Windows.");
            }
            config(['iam.crypto.openssl_config' => $cnf]);
            $this->app->forgetInstance(TokenSigner::class);
        }

        $this->recordEvents();

        $checkpointer = app(AuditCheckpointer::class);
        $checkpoint = $checkpointer->checkpoint(self::STREAM);

        $this->assertInstanceOf(AuditCheckpoint::class, $checkpoint);
        $this->assertSame(self::STREAM, $checkpoint->stream);
        $this->assertSame(3, $checkpoint->up_to_seq);
        $this->assertNotEmpty($checkpoint->signature, 'il checkpoint deve portare una firma');

        // Persistito a DB e legato alla testa corrente.
        $head = AuditHead::query()->find(self::STREAM);
        $this->assertSame($head->hash, $checkpoint->head_hash);
        $this->assertDatabaseHas('iam_audit_checkpoints', ['stream' => self::STREAM, 'up_to_seq' => 3]);

        // La firma ES256 è verificabile e lega esattamente stream/seq/head_hash.
        $verify = $checkpointer->verify($checkpoint);
        $this->assertTrue($verify->valid, 'la firma del checkpoint deve essere valida');

        // Lo stesso via il comando artisan reale.
        $this->artisan('iam:audit:checkpoint', ['--stream' => self::STREAM])
            ->assertExitCode(0);
    }

    public function test_siem_export_emits_the_events(): void
    {
        [$e1, $e2, $e3] = $this->recordEvents();

        // Export CEF: una riga per evento, con header CEF e l'hash di catena come anchoring.
        $cefRows = iterator_to_array(app(AuditExporter::class)->export(self::STREAM, null, null, 'cef'));
        $this->assertCount(3, $cefRows);
        $this->assertStringStartsWith('CEF:0|Padosoft|Laravel IAM|', $cefRows[0]);
        $this->assertStringContainsString('grant.assigned', $cefRows[0]);
        $this->assertStringContainsString('cs3='.$e1->hash, $cefRows[0], 'il CEF deve trasportare l\'hash della catena');
        $this->assertStringContainsString('policy.approved', $cefRows[1]);

        // Export OCSF: schema cross-vendor, con i campi IAM in `unmapped` (seq/hash/stream).
        $ocsfRows = iterator_to_array(app(AuditExporter::class)->export(self::STREAM, null, null, 'ocsf'));
        $this->assertCount(3, $ocsfRows);
        $this->assertSame(3005, $ocsfRows[0]['class_uid']);
        $this->assertSame('grant.assigned', $ocsfRows[0]['unmapped']['iam_event_type']);
        $this->assertSame($e3->hash, $ocsfRows[2]['unmapped']['iam_hash']);

        // Lo stesso flusso via il comando artisan reale (formato LEEF su stdout).
        $this->artisan('iam:audit:export', ['--stream' => self::STREAM, '--format' => 'leef'])
            ->expectsOutputToContain('LEEF:2.0|Padosoft|Laravel IAM|')
            ->assertExitCode(0);
    }
}
