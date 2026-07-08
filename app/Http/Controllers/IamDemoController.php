<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Domain\Audit\Pii\AuditRecorder;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;

/**
 * Laravel IAM — demo dashboard.
 *
 * Proves the whole ecosystem is installed AND functional in a single app:
 * lists the installed packages / iam:* commands / migrated iam_* tables, then
 * runs LIVE Policy Decision Point checks through the real NativeSqlEngine
 * (bound by laravel-iam-server) to show deterministic allow / fail-closed deny.
 */
class IamDemoController extends Controller
{
    private const PACKAGES = [
        'padosoft/laravel-iam-contracts' => 'Shared interfaces & DTOs (dependency root)',
        'padosoft/laravel-iam-server' => 'Identity, PDP, OAuth/OIDC, audit, governance, Admin API',
        'padosoft/laravel-iam-client' => 'iam.auth / iam.can middleware + Gate adapter',
        'padosoft/laravel-iam-ai' => 'Advisory-only AI governance (disabled by default)',
        'padosoft/laravel-iam-directory' => 'LDAP/AD login + JIT provisioning',
        'padosoft/laravel-iam-bridge-spatie-permission' => 'Migration bridge from spatie/laravel-permission',
    ];

    public function show()
    {
        // IAM-42 — DEMO ONLY. A real application must NEVER provision grants with a direct Eloquent write
        // (it bypasses the tamper-evident audit invariant) nor ship fixed credentials: grants are provisioned
        // through the AUDITED Admin API / manifests, and demo users come from a guarded seeder with a
        // per-environment password. Here the seeding is (a) skipped in production, (b) sourced from
        // DEMO_PASSWORD, and (c) routed through an audited path (an audit event per seeded grant).
        $demoPassword = (string) env('DEMO_PASSWORD', 'password');
        if (! app()->environment('production')) {
            $this->seedDemoData($demoPassword);
        }

        $engine = app(AuthorizationEngine::class);

        // If someone is logged in, show the grants IAM decides for THEM (the "assume IAM-decided grants" demo).
        $me = Auth::user();
        $myGrants = $me === null ? null : array_map(fn (string $p): array => [
            'permission' => $p,
            'allowed' => (bool) ($engine->check(['subject' => ['type' => 'user', 'id' => (string) $me->getKey()], 'permission' => $p])['allowed'] ?? false),
        ], ['invoices.view', 'invoices.create', 'invoices.delete']);

        $scenarios = [
            ['label' => 'user:1 → invoices.view', 'note' => 'has a permit grant', 'q' => ['subject' => ['type' => 'user', 'id' => '1'], 'permission' => 'invoices.view', 'explain' => true]],
            ['label' => 'user:1 → invoices.delete', 'note' => 'no grant for this permission', 'q' => ['subject' => ['type' => 'user', 'id' => '1'], 'permission' => 'invoices.delete', 'explain' => true]],
            ['label' => 'user:2 → invoices.view', 'note' => 'different subject, no grant', 'q' => ['subject' => ['type' => 'user', 'id' => '2'], 'permission' => 'invoices.view', 'explain' => true]],
        ];

        $decisions = array_map(static function (array $s) use ($engine): array {
            $s['decision'] = $engine->check($s['q']);

            return $s;
        }, $scenarios);

        $commands = collect(Artisan::all())->keys()
            ->filter(fn (string $n): bool => str_starts_with($n, 'iam:'))
            ->sort()->values();

        $tables = collect(DB::select("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'iam_%' ORDER BY name"))
            ->pluck('name');

        $demoClient = OauthClient::query()->where('application_key', 'demo')->first();

        return view('iam-demo', [
            'packages' => self::PACKAGES,
            'commands' => $commands,
            'tables' => $tables,
            'decisions' => $decisions,
            'me' => $me,
            'myGrants' => $myGrants,
            'demoClientId' => $demoClient?->client_id,
            'demoCreds' => ['email' => 'demo@example.com', 'password' => env('DEMO_PASSWORD', 'password')],
        ]);
    }

    /**
     * DEMO-ONLY bootstrap of a login-able operator + a couple of permit grants, so the page has live data.
     * Guarded to non-production by the caller. Each seeded grant is emitted to the audit log (invariant #4:
     * every mutation is audited) — i.e. provisioned through an audited path, not a silent direct write.
     */
    private function seedDemoData(string $password): void
    {
        $demoUser = User::query()->firstOrCreate(
            ['email' => 'demo@example.com'],
            ['name' => 'Demo User', 'password' => Hash::make($password)],
        );

        $this->seedGrant('user', '1', 'invoices.view');
        foreach (['invoices.view', 'invoices.create'] as $permit) {
            $this->seedGrant('user', (string) $demoUser->getKey(), $permit);
        }
    }

    private function seedGrant(string $subjectType, string $subjectId, string $permission): void
    {
        $grant = Grant::query()->firstOrCreate(
            ['subject_type' => $subjectType, 'subject_id' => $subjectId, 'privilege_type' => 'permission', 'privilege_key' => $permission, 'effect' => 'permit'],
            ['valid_from' => now(), 'source' => 'demo'],
        );

        // Audita solo alla creazione effettiva (idempotenza: niente doppio audit sui re-run).
        if ($grant->wasRecentlyCreated) {
            app(AuditRecorder::class)->record([
                'stream' => 'governance',
                'event_type' => 'iam.grant.granted',
                'target_type' => 'grant',
                'target_id' => $grant->id,
                'metadata_json' => ['source' => 'demo-seed', 'subject' => $subjectType.':'.$subjectId, 'permission' => $permission],
            ]);
        }
    }

    public function json()
    {
        return response()->json([
            'app' => 'Laravel IAM — demo (all packages, single app)',
            'packages_installed' => array_keys(self::PACKAGES),
            'iam_artisan_commands' => collect(Artisan::all())->keys()->filter(fn ($n) => str_starts_with($n, 'iam:'))->sort()->values(),
            'iam_tables_migrated' => collect(DB::select("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'iam_%' ORDER BY name"))->pluck('name'),
        ], 200, [], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
