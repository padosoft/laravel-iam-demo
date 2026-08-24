<?php

use App\Http\Controllers\DelegationDemoController;
use App\Http\Controllers\IamDemoController;
use App\Http\Controllers\OnboardingController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Laravel IAM — demo
|--------------------------------------------------------------------------
| The homepage is a live dashboard proving the whole IAM ecosystem is
| installed and functional in this single app: installed packages, iam:*
| commands, migrated iam_* tables, and real-time PDP allow/deny decisions
| run through laravel-iam-server's NativeSqlEngine.
*/
Route::get('/', [IamDemoController::class, 'show']);
Route::get('/iam', [IamDemoController::class, 'show']);
Route::get('/iam.json', [IamDemoController::class, 'json']);

// Interactive onboarding + auth demo (see OnboardingController):
//   register → apply the committed manifest, mint the OAuth client + one-time secret
//   login/logout → authenticate against the IAM user store, then the dashboard shows IAM-decided grants
Route::post('/demo/register', [OnboardingController::class, 'register'])->name('demo.register');
Route::post('/demo/login', [OnboardingController::class, 'login'])->name('demo.login');
Route::post('/demo/logout', [OnboardingController::class, 'logout'])->name('demo.logout');

// Delegated access walkthrough (laravel-iam-agents): register agent -> consent (the module's own
// self-service endpoints at /iam/me/delegations do the challenge+grant) -> RFC 8693 exchange ->
// intersection check -> revoke -> the next exchange fails. See the "Delegated access" panel.
Route::middleware('auth')->group(function () {
    Route::post('/demo/delegation/setup', [DelegationDemoController::class, 'setup'])->name('demo.delegation.setup');
    Route::post('/demo/delegation/exchange', [DelegationDemoController::class, 'exchange'])->name('demo.delegation.exchange');
    Route::post('/demo/delegation/check', [DelegationDemoController::class, 'check'])->name('demo.delegation.check');
    Route::post('/demo/delegation/revoke', [DelegationDemoController::class, 'revoke'])->name('demo.delegation.revoke');
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
