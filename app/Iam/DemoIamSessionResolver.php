<?php

namespace App\Iam;

use Illuminate\Http\Request;
use Padosoft\Iam\Agents\Support\DelegationSessionResolver;
use Padosoft\Iam\Contracts\Identity\SessionRef;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;

/**
 * Tells the agents module WHERE this app keeps the user's IAM session id: the demo login
 * (OnboardingController::login) starts a real SessionRegistry session and stashes its sid in the
 * Laravel session. Fail-closed by construction: no sid, or a sid that is no longer alive in the
 * registry, resolves to null — and the native consent verifier refuses without a live session.
 */
class DemoIamSessionResolver implements DelegationSessionResolver
{
    public function __construct(private readonly SessionRegistry $sessions) {}

    public function resolve(Request $request): ?SessionRef
    {
        $sid = $request->session()->get('iam_sid');
        if (! is_string($sid) || $sid === '') {
            return null;
        }

        return $this->sessions->active($sid) ? new SessionRef($sid) : null;
    }
}
