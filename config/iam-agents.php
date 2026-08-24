<?php

use App\Iam\DemoIamSessionResolver;
use Padosoft\Iam\Agents\Consent\IamNativeConsentVerifier;

/*
 * Demo overrides for padosoft/laravel-iam-agents (all other keys keep the package defaults).
 * The module is fail-closed out of the box: without a ConsentVerifier and a session resolver it
 * creates ZERO delegation grants — these two bindings are the app-side wiring every host must do.
 */
return [
    'consent' => [
        'purpose' => 'iam-delegation-grant',
        'required_aal' => 'aal2',

        // Native IAM step-up (real single-use claim). The factor behind it is DemoTotpVerifier,
        // bound ONLY outside production (AppServiceProvider) — see that class' warning.
        'verifier' => IamNativeConsentVerifier::class,

        // Where THIS app keeps the user's IAM sid: set at login by OnboardingController.
        'session_resolver' => DemoIamSessionResolver::class,
    ],
];
