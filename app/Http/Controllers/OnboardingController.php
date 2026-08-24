<?php

namespace App\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Padosoft\Iam\Contracts\Identity\SessionMeta;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Applications\Manifest\ManifestRegistry;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;

/**
 * The interactive half of the demo: onboard THIS app into IAM from a committed manifest (mint its OAuth
 * client + a one-time secret), then log a user in against the IAM user store and show the grants the PDP
 * decides for them. Everything runs in-process against the real laravel-iam-server services.
 */
class OnboardingController extends Controller
{
    /**
     * "Register this app in IAM" — submit + approve + apply the committed iam-manifest.json. Apply mints the
     * OAuth client (cli_demo) and a client secret shown exactly ONCE (hashed at rest); the UI then tells you
     * where to paste it. Idempotent: re-running rotates nothing you don't ask for — it re-applies the manifest.
     */
    public function register(ManifestRegistry $registry): RedirectResponse
    {
        $payload = json_decode((string) file_get_contents(base_path('iam-manifest.json')), true);
        if (! is_array($payload)) {
            return redirect('/')->withErrors(['manifest' => 'iam-manifest.json is missing or invalid.']);
        }

        try {
            $manifest = $registry->submit($payload, 'demo-ui');
            // Adding redirect_uris on a new app is a "sensitive" change gated by a human approval — here the
            // demo self-approves so the button is one-click.
            $registry->approve($manifest, 'demo-ui');
            $registry->apply($manifest);
        } catch (\Throwable $e) {
            return redirect('/')->withErrors(['manifest' => 'Apply failed: '.$e->getMessage()]);
        }

        $client = OauthClient::query()->where('application_key', 'demo')->first();

        return redirect('/')->with('registered', [
            'client_id' => $client?->client_id,
            'client_secret' => $registry->lastGeneratedSecret(), // one-time
        ]);
    }

    /** "Log in against IAM" — authenticate against the IAM user store; the dashboard then shows your grants. */
    public function login(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        if (! Auth::attempt($data, true)) {
            return redirect('/')->withErrors(['email' => 'Invalid credentials.'])->withInput();
        }

        $request->session()->regenerate();

        // Start a REAL IAM session for the delegation demo: the RFC 8693 exchange re-verifies this
        // session's liveness on every call, and the consent step-up is anchored to it. Logging out
        // revokes it — after which the next exchange fails (revocation freshness, by design).
        // iam_sessions.user_id is FK'd to iam_users: the demo mirrors its local operator into the
        // IAM user store (in production your users ARE IAM users — one identity, no mirroring).
        $iamUser = User::query()->firstOrCreate(
            ['email' => (string) $request->user()?->email],
            ['name' => (string) $request->user()?->name],
        );
        $session = app(SessionRegistry::class)->start(
            new SubjectRef('user', $iamUser->id),
            new SessionMeta,
        );
        $request->session()->put('iam_sid', $session->id);

        return redirect('/');
    }

    public function logout(Request $request): RedirectResponse
    {
        // Revoke the IAM session too: any delegated-token exchange for this user now fails.
        $sid = $request->session()->get('iam_sid');
        if (is_string($sid) && $sid !== '') {
            app(SessionRegistry::class)->revokeSession($sid, 'demo-logout');
        }

        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/');
    }
}
