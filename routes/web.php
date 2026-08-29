<?php

use App\Http\Controllers\DelegationDemoController;
use App\Http\Controllers\IamDemoController;
use App\Http\Controllers\OnboardingController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Padosoft\Iam\Client\Http\Middleware\IamCanDelegated;

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
    Route::post('/demo/delegation/call', [DelegationDemoController::class, 'call'])->name('demo.delegation.call');
    Route::post('/demo/delegation/check', [DelegationDemoController::class, 'check'])->name('demo.delegation.check');
    Route::post('/demo/delegation/preview', [DelegationDemoController::class, 'preview'])->name('demo.delegation.preview');
    Route::post('/demo/delegation/chain', [DelegationDemoController::class, 'chain'])->name('demo.delegation.chain');
    Route::post('/demo/delegation/revoke', [DelegationDemoController::class, 'revoke'])->name('demo.delegation.revoke');
});

/*
|--------------------------------------------------------------------------
| The agent-facing API — REAL enforcement, no demo shortcuts
|--------------------------------------------------------------------------
| These routes accept ONLY delegated bearers minted through the RFC 8693
| exchange: iam.can.delegated (laravel-iam-client) verifies the token via
| mandatory introspection, decides on the user ∩ agent intersection, and
| hydrates Laravel Context — so the Log lines below carry iam_delegation
| (actors = the agent, sub = the delegating user) automatically.
| A plain user token, a made-up token, or no token at all ⇒ 401. An action
| outside the intersection (invoices.create: the USER holds it, the demo
| agent does not) ⇒ 403.
*/
Route::middleware([IamCanDelegated::class.':invoices.view'])->get('/demo/agent-api/invoices', function (Request $request) {
    Log::info('[agent-api] invoices listed by a delegated caller');

    return response()->json([
        'invoices' => [
            ['id' => 'INV-001', 'total' => '120.00'],
            ['id' => 'INV-002', 'total' => '84.50'],
        ],
        // The Context the middleware hydrated: an AGENT is acting, the sub stays the USER.
        'iam_delegation' => Context::get('iam_delegation'),
    ]);
});

Route::middleware([IamCanDelegated::class.':invoices.create'])->post('/demo/agent-api/invoices', function (Request $request) {
    // The demo agent never gets here (invoices.create is outside its intersection): this handler
    // exists to prove the DENY happens in the middleware, not in application code.
    Log::info('[agent-api] invoice created by a delegated caller');

    return response()->json(['created' => true, 'iam_delegation' => Context::get('iam_delegation')], 201);
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
