<?php

namespace App\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Contracts\Delegation\ActClaim;
use Padosoft\Iam\Contracts\Delegation\ActorRef;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegatedAuthorizationEngine;
use Padosoft\Iam\Contracts\Delegation\DelegationChain;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Padosoft\Iam\Domain\OAuth\Models\OauthScope;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

/**
 * The delegated-access walkthrough (laravel-iam-agents): register an agent → the logged-in user
 * consents (real step-up-bound consent via the module's own self-service endpoints) → RFC 8693
 * exchange on the REAL token endpoint → the intersection PDP allows/denies → revoke → the next
 * exchange fails. Everything runs against the real services — no mocks, no fake tokens.
 */
class DelegationDemoController extends Controller
{
    public const AGENT_NAME = 'Invoice Copilot';

    public const AGENT_CLIENT_ID = 'cli_demo_agent';

    /**
     * Step 1 — register + approve the demo agent. In the console this is two human actions
     * (create, then approve pasting the JWKS); the demo compresses them into one click and uses
     * client_secret auth to keep the walkthrough dependency-free (agents in production use
     * private_key_jwt — see the module README). The agent's PDP permission is invoices.view ONLY:
     * that asymmetry vs the user (who also holds invoices.create) is what makes the intersection
     * visible in step 4.
     */
    public function setup(Request $request): RedirectResponse
    {
        OauthScope::query()->firstOrCreate(['identifier' => 'invoices.view'], ['description' => 'Read invoices']);

        $secret = Str::random(32);
        $client = OauthClient::query()->updateOrCreate(
            ['client_id' => self::AGENT_CLIENT_ID],
            [
                'name' => self::AGENT_NAME,
                'redirect_uris' => [],
                'grants' => [ActClaim::GRANT_TYPE_TOKEN_EXCHANGE],
                'scopes' => ['invoices.view'],
                'is_confidential' => true,
            ],
        );
        $client->secret = Hash::make($secret);
        $client->save();
        // The exchange in step 3 runs server-side in this demo, so the secret lives in the session
        // (in production the ORCHESTRATOR holds the agent credential — never the browser, never the LLM).
        $request->session()->put('delegation_demo.agent_secret', $secret);

        $agent = Agent::query()->firstOrCreate(
            ['client_id' => self::AGENT_CLIENT_ID],
            [
                'id' => Agent::newId(),
                'name' => self::AGENT_NAME,
                'operator' => 'demo',
                'max_scopes' => ['invoices.view'],
                'status' => AgentStatus::Active->value,
            ],
        );
        if ($agent->status !== AgentStatus::Active->value) {
            $agent->fill(['status' => AgentStatus::Active->value])->save(); // re-run after a suspend demo
        }

        // The AGENT layer of the intersection: the agent itself may view invoices — and nothing else.
        Grant::query()->firstOrCreate(
            ['subject_type' => 'agent', 'subject_id' => $agent->id, 'privilege_type' => 'permission', 'privilege_key' => 'invoices.view', 'effect' => 'permit'],
            ['valid_from' => now(), 'source' => 'demo'],
        );

        return redirect('/')->with('delegation_flash', [
            'step' => 'setup',
            'ok' => true,
            'detail' => 'Agent "'.self::AGENT_NAME.'" active ('.$agent->id.') — OAuth client '.self::AGENT_CLIENT_ID.' with the token-exchange grant only. PDP permission: invoices.view.',
        ]);
    }

    /**
     * Step 3 — the RFC 8693 exchange on the app's REAL token endpoint (an internal sub-request:
     * same route, same league AuthorizationServer, same audit). The user's subject token is minted
     * here for convenience — in production the orchestrator already holds it from the user's OAuth
     * login — and it carries the sid of the CURRENT IAM session, so logout/revocation bite.
     */
    public function exchange(Request $request): RedirectResponse
    {
        $userId = (string) Auth::id();
        $sid = $request->session()->get('iam_sid');
        $secret = $request->session()->get('delegation_demo.agent_secret');
        if ($userId === '' || ! is_string($sid) || ! is_string($secret)) {
            return redirect('/')->with('delegation_flash', ['step' => 'exchange', 'ok' => false, 'detail' => 'Log in and run setup first.']);
        }

        $subjectToken = app(TokenSigner::class)->issue([
            'sub' => $userId, 'sid' => $sid, 'aud' => 'cli_demo', 'scope' => 'openid',
        ], 900);

        $params = [
            'grant_type' => ActClaim::GRANT_TYPE_TOKEN_EXCHANGE,
            'client_id' => self::AGENT_CLIENT_ID,
            'client_secret' => $secret,
            'subject_token' => $subjectToken,
            'subject_token_type' => ActClaim::TOKEN_TYPE_ACCESS,
            'scope' => 'invoices.view',
        ];

        // Internal sub-request (NOT an HTTP self-call: `artisan serve` is single-threaded).
        $sub = SymfonyRequest::create(route('iam.oauth.token'), 'POST', $params);
        $response = app()->handle($sub);
        $body = json_decode((string) $response->getContent(), true) ?: [];

        if ($response->getStatusCode() !== 200) {
            $request->session()->forget('delegation_demo.token');

            return redirect('/')->with('delegation_flash', [
                'step' => 'exchange', 'ok' => false,
                'detail' => 'Exchange REFUSED — '.($body['error'] ?? 'error').(isset($body['error_description']) ? ': '.$body['error_description'] : '')
                    .' (the detailed reason is in the delegation audit stream below).',
            ]);
        }

        $claims = app(TokenSigner::class)->parse($body['access_token']);
        $request->session()->put('delegation_demo.token', [
            'claims' => [
                'sub' => $claims['sub'] ?? null,
                'act' => $claims['act'] ?? null,
                'pds_dgr' => $claims['pds_dgr'] ?? null,
                'scope' => $claims['scope'] ?? null,
            ],
            'expires_in' => $body['expires_in'] ?? null,
            'issued_token_type' => $body['issued_token_type'] ?? null,
        ]);

        return redirect('/')->with('delegation_flash', [
            'step' => 'exchange', 'ok' => true,
            'detail' => 'Delegated token issued: sub='.($claims['sub'] ?? '?').' act='.json_encode($claims['act'] ?? null)
                .' grant='.($claims['pds_dgr'] ?? '?').' — TTL '.($body['expires_in'] ?? '?').'s, non-refreshable.',
        ]);
    }

    /**
     * Step 4 — the intersection rule, live: invoices.view passes (user ∧ agent both allowed);
     * invoices.create is DENIED even though the USER holds it — the agent's layer doesn't. Never
     * the union: a hijacked agent cannot ride the user's wider permissions.
     */
    public function check(Request $request): RedirectResponse
    {
        $userId = (string) Auth::id();
        $token = $request->session()->get('delegation_demo.token');
        $agent = Agent::query()->where('client_id', self::AGENT_CLIENT_ID)->first();
        if ($userId === '' || ! is_array($token) || $agent === null) {
            return redirect('/')->with('delegation_flash', ['step' => 'check', 'ok' => false, 'detail' => 'Run the exchange first.']);
        }

        $engine = app(DelegatedAuthorizationEngine::class);
        $chain = new DelegationChain(ActorRef::fromAgentId($agent->id));
        $grantId = $token['claims']['pds_dgr'] ?? null;

        $results = [];
        foreach (['invoices.view', 'invoices.create'] as $permission) {
            $decision = $engine->checkDelegated(
                new SubjectRef('user', $userId),
                $chain,
                ['permission' => $permission] + (is_string($grantId) ? ['delegation_grant_id' => $grantId] : []),
            );
            $results[] = $permission.' ⇒ '.(($decision['allowed'] ?? false) ? 'ALLOW' : 'DENY')
                .(isset($decision['reason']) ? ' ('.$decision['reason'].')' : '');
        }

        return redirect('/')->with('delegation_flash', [
            'step' => 'check', 'ok' => true,
            'detail' => implode(' · ', $results).' — the user HAS invoices.create; the agent does not: intersection, never union.',
        ]);
    }

    /**
     * Step 5 — revoke, then watch the next exchange fail. Uses the module's own store (the same
     * path the self-service DELETE and the console kill-switch go through), so the revocation is
     * audited with who revoked.
     */
    public function revoke(Request $request): RedirectResponse
    {
        $userId = (string) Auth::id();
        $grant = DelegationGrantModel::query()
            ->where('user_type', 'user')->where('user_id', $userId)
            ->where('status', 'active')
            ->latest('created_at')->first();
        if ($userId === '' || $grant === null) {
            return redirect('/')->with('delegation_flash', ['step' => 'revoke', 'ok' => false, 'detail' => 'No active delegation grant to revoke.']);
        }

        app(DelegationGrantStore::class)
            ->revoke($grant->id, new SubjectRef('user', $userId));
        $request->session()->forget('delegation_demo.token');

        return redirect('/')->with('delegation_flash', [
            'step' => 'revoke', 'ok' => true,
            'detail' => 'Grant '.$grant->id.' revoked. Now press "Exchange" again: the server answers invalid_grant — revocation lands at the NEXT check, not at token expiry.',
        ]);
    }

    /**
     * Panel state for the dashboard: current agent, the logged-in user's grants, the delegated
     * token claims held in session, and the tail of the delegation audit stream (both identities
     * on every event).
     *
     * @return array<string, mixed>
     */
    public static function panelState(): array
    {
        $agent = Agent::query()->where('client_id', self::AGENT_CLIENT_ID)->first();
        $userId = Auth::id();

        $grants = $userId === null ? [] : DelegationGrantModel::query()
            ->where('user_type', 'user')->where('user_id', (string) $userId)
            ->latest('created_at')->limit(5)->get()
            ->map(fn (DelegationGrantModel $g): array => [
                'id' => $g->id,
                'scopes' => $g->scopes,
                'purpose' => $g->purpose,
                'status' => $g->status,
                'consent_aal' => $g->consent_aal,
            ])->all();

        $audit = AuditEvent::query()->where('stream', 'delegation')
            ->latest('id')->limit(8)->get()
            ->map(fn (AuditEvent $e): array => [
                'event_type' => $e->event_type,
                'metadata' => $e->metadata_json,
            ])->all();

        return [
            'agent' => $agent === null ? null : ['id' => $agent->id, 'name' => $agent->name, 'status' => $agent->status, 'max_scopes' => $agent->max_scopes],
            'grants' => $grants,
            'token' => session('delegation_demo.token'),
            'audit' => $audit,
            'stepup_code' => app()->environment('production') ? null : (string) env('DEMO_STEPUP_CODE', '123456'),
        ];
    }
}
