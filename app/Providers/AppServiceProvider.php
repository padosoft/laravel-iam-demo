<?php

namespace App\Providers;

use App\Iam\DemoTotpVerifier;
use Illuminate\Support\ServiceProvider;
use Padosoft\Iam\Contracts\Assurance\FactorVerifier;

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
        // DEMO ONLY — the factor behind the native step-up (delegation consent). In production the
        // server's fail-closed default stays (no factor configured => no step-up => no consent):
        // wire your real TOTP/passkey verifier or rebel-step-up instead of this stand-in.
        if (! $this->app->environment('production')) {
            $this->app->bind(FactorVerifier::class, DemoTotpVerifier::class);
        }
    }
}
