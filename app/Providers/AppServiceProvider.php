<?php

namespace App\Providers;

use App\Http\Controllers\DelegationDemoController;
use App\Iam\DemoTotpVerifier;
use App\Iam\KernelDispatchHandler;
use App\Models\User;
use App\Routines\InvoiceReminderTarget;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\ServiceProvider;
use Padosoft\Iam\Client\Auth\DelegatedTokenVerifier;
use Padosoft\Iam\Client\Support\DelegatedBearerInspector;
use Padosoft\Iam\Contracts\Assurance\FactorVerifier;
use Padosoft\Routines\Targets\TargetRegistry;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // The demo's routine target: chasing overdue invoices, and asking a human before writing
        // one off. Registered from the application's own provider - the scheduler has no list of
        // what can be run, which is what lets a package add a target without the core changing.
        $this->callAfterResolving(TargetRegistry::class, function (TargetRegistry $registry): void {
            $registry->register(new InvoiceReminderTarget);
        });

        // The panel shows an email instead of `user:7`. The core does not know this app's user
        // model, so it does not guess: without a resolver it shows the canonical identifier,
        // which is still true, just less useful.
        config([
            'routines.owner_label_resolver' => fn (string $owner): ?string => str_starts_with($owner, 'user:')
                ? User::find((int) substr($owner, 5))?->email
                : null,
        ]);

        // DEMO ONLY — the factor behind the native step-up (delegation consent). In production the
        // server's fail-closed default stays (no factor configured => no step-up => no consent):
        // wire your real TOTP/passkey verifier or rebel-step-up instead of this stand-in.
        if (! $this->app->environment('production')) {
            $this->app->bind(FactorVerifier::class, DemoTotpVerifier::class);
        }

        // DEMO ONLY — the resource-server half of delegated access lives in this same app, so the
        // client SDK's introspection-mandatory verifier travels through an internal sub-request
        // (KernelDispatchHandler) to the app's own /oauth/introspect, authenticated as the demo
        // agent client. Everything else is the REAL enforcement path: iam.can.delegated ->
        // introspection -> checkDelegated on the intersection -> Laravel Context hydration.
        $this->app->bind(DelegatedTokenVerifier::class, fn () => new DelegatedTokenVerifier(
            new GuzzleClient(['handler' => HandlerStack::create(new KernelDispatchHandler)]),
            new DelegatedBearerInspector,
            route('iam.oauth.introspect'),
            DelegationDemoController::AGENT_CLIENT_ID,
            is_string($secret = Cache::get('delegation_demo.agent_secret')) ? $secret : null,
        ));
    }
}
