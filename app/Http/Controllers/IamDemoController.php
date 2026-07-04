<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
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
        // Idempotently seed ONE direct permit grant: user:1 may "invoices.view".
        // (A real app grants via roles/manifests; a direct permission grant keeps the demo self-contained.)
        Grant::query()->firstOrCreate(
            [
                'subject_type' => 'user',
                'subject_id' => '1',
                'privilege_type' => 'permission',
                'privilege_key' => 'invoices.view',
                'effect' => 'permit',
            ],
            ['valid_from' => now(), 'source' => 'demo'],
        );

        // A demo operator you can actually log in as (email demo@example.com / password), granted two of the
        // three invoice permissions — so after login the "your grants" panel shows real IAM allow/deny.
        $demoUser = User::query()->firstOrCreate(
            ['email' => 'demo@example.com'],
            ['name' => 'Demo User', 'password' => Hash::make('password')],
        );
        foreach (['invoices.view', 'invoices.create'] as $permit) {
            Grant::query()->firstOrCreate(
                ['subject_type' => 'user', 'subject_id' => (string) $demoUser->getKey(), 'privilege_type' => 'permission', 'privilege_key' => $permit, 'effect' => 'permit'],
                ['valid_from' => now(), 'source' => 'demo'],
            );
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
            'demoCreds' => ['email' => 'demo@example.com', 'password' => 'password'],
        ]);
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
