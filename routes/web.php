<?php

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

/*
|--------------------------------------------------------------------------
| Laravel IAM — demo introspection
|--------------------------------------------------------------------------
| A self-contained page that proves the whole IAM ecosystem is installed and
| booted in this single app: the auto-discovered packages, the IAM artisan
| commands, and the migrated IAM database schema. No external server needed.
*/
Route::get('/iam', function () {
    $packages = [
        'padosoft/laravel-iam-contracts',
        'padosoft/laravel-iam-server',
        'padosoft/laravel-iam-client',
        'padosoft/laravel-iam-ai',
        'padosoft/laravel-iam-directory',
        'padosoft/laravel-iam-bridge-spatie-permission',
    ];

    $iamCommands = collect(Artisan::all())
        ->keys()
        ->filter(fn (string $name): bool => str_starts_with($name, 'iam:'))
        ->values();

    // List the IAM tables actually present in the (SQLite) schema.
    $tables = collect(DB::select(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'iam_%' ORDER BY name"
    ))->pluck('name');

    return response()->json([
        'app' => 'Laravel IAM — demo (all packages, single app)',
        'packages_installed' => $packages,
        'iam_artisan_commands' => $iamCommands,
        'iam_tables_migrated' => $tables,
        'note' => 'See README.md for example iam.auth / iam.can route protection.',
    ], 200, [], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
});

/*
|--------------------------------------------------------------------------
| Example: protecting routes with the IAM client middleware
|--------------------------------------------------------------------------
| The client package ships `iam.auth` (authenticated IAM subject) and
| `iam.can:<permission>` (PDP authorization, fail-closed). Uncomment once you
| have an issuer + signing keys configured (see README "Going further").
|
| Route::middleware(['iam.auth', 'iam.can:invoices.view'])->group(function () {
|     Route::get('/invoices', fn () => 'You may view invoices.');
| });
*/
