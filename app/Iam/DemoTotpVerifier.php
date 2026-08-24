<?php

namespace App\Iam;

use Padosoft\Iam\Contracts\Assurance\FactorVerifier;
use Padosoft\Iam\Contracts\Support\SubjectRef;

/**
 * DEMO ONLY — a stand-in for the TOTP/passkey factor behind the native step-up. It accepts the code
 * printed on the demo page (DEMO_STEPUP_CODE, default 123456) so the consent flow can be walked
 * without configuring Fortify/WebAuthn. Bound in AppServiceProvider ONLY outside production: in a
 * real deployment you leave the server's fail-closed default (or wire your real FactorVerifier /
 * rebel-step-up), and this class must never be bound.
 */
class DemoTotpVerifier implements FactorVerifier
{
    public function verify(SubjectRef $subject, array $payload): bool
    {
        $expected = (string) env('DEMO_STEPUP_CODE', '123456');

        return is_string($payload['code'] ?? null) && hash_equals($expected, $payload['code']);
    }
}
