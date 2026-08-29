<?php

namespace App\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use League\OAuth2\Server\AuthorizationServer;
use Padosoft\Iam\Agents\Consent\ConsentPreview;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Contracts\Delegation\ActClaim;
use Padosoft\Iam\Contracts\Delegation\ActorRef;
use Padosoft\Iam\Contracts\Delegation\AgentStatus;
use Padosoft\Iam\Contracts\Delegation\DelegatedAuthorizationEngine;
use Padosoft\Iam\Contracts\Delegation\DelegationChain;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStatus;
use Padosoft\Iam\Contracts\Delegation\DelegationGrantStore;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Governance\Reviews\CampaignEngine;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewItem;
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

    /** The downstream agent of the multi-hop step: the one A hands the work to. */
    public const HOP2_NAME = 'Invoice Archiver';

    public const HOP2_CLIENT_ID = 'cli_demo_agent_hop2';

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
        // The exchange (step 3) and the introspection behind iam.can.delegated (step 4) both run
        // server-side: the plaintext secret lives in the app cache — the demo's stand-in for the
        // ORCHESTRATOR's credential store (never the browser, never the LLM).
        Cache::forever('delegation_demo.agent_secret', $secret);

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
        $secret = Cache::get('delegation_demo.agent_secret');
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
            // The raw JWT stays server-side (the orchestrator's hand) — step 4 presents it as the
            // Bearer on the agent-facing API. It is NEVER rendered to the browser.
            'jwt' => $body['access_token'],
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
     * Step 4 — THE proof: the agent calls a REAL protected API. The routes under /demo/agent-api
     * are guarded by the client SDK's iam.can.delegated middleware — bearer required, verified via
     * mandatory introspection, decided on the user ∩ agent intersection. Three calls show the
     * whole contract: no token ⇒ 401; invoices.view (inside the intersection) ⇒ 200 — and the
     * response echoes the Laravel Context the middleware hydrated (an AGENT is acting, but `sub`
     * is the USER); invoices.create (the user has it, the agent does NOT) ⇒ 403.
     */
    public function call(Request $request): RedirectResponse
    {
        $token = $request->session()->get('delegation_demo.token');
        $jwt = is_array($token) ? ($token['jwt'] ?? null) : null;
        if (! is_string($jwt)) {
            return redirect('/')->with('delegation_flash', ['step' => 'call', 'ok' => false, 'detail' => 'Run the exchange first.']);
        }

        $hit = function (string $method, ?string $bearer): array {
            $sub = SymfonyRequest::create(url('/demo/agent-api/invoices'), $method);
            $sub->headers->set('Accept', 'application/json');
            if ($bearer !== null) {
                $sub->headers->set('Authorization', 'Bearer '.$bearer);
            }
            $response = app()->handle($sub);

            return ['status' => $response->getStatusCode(), 'body' => json_decode((string) $response->getContent(), true)];
        };

        $results = [
            'no_token' => $hit('GET', null),          // 401: this surface ONLY accepts delegated bearers
            'view' => $hit('GET', $jwt),              // 200: inside the intersection
            'create' => $hit('POST', $jwt),           // 403: the USER holds invoices.create, the agent does not
        ];

        $request->session()->put('delegation_demo.calls', $results);

        return redirect('/')->with('delegation_flash', [
            'step' => 'call',
            'ok' => $results['no_token']['status'] === 401 && $results['view']['status'] === 200 && $results['create']['status'] === 403,
            'detail' => 'GET without token ⇒ '.$results['no_token']['status']
                .' · GET invoices (view, in intersection) ⇒ '.$results['view']['status']
                .' · POST invoices (create, agent lacks it) ⇒ '.$results['create']['status']
                .' — the 200 response and the demo log carry iam_delegation: an AGENT acts, the sub stays the USER.',
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
     * Step 4b — the consent PREVIEW: what would this delegation actually cover?
     *
     * A consent screen that says "invoices.view" asks the user to approve a NAME. This asks the
     * PDP's reverse index on BOTH subjects and shows the intersection — the concrete resources
     * the agent could really touch. Truncation is declared, because a preview that understates
     * the blast radius is worse than no preview.
     */
    public function preview(Request $request): RedirectResponse
    {
        $userId = (string) Auth::id();
        $agent = Agent::query()->where('client_id', self::AGENT_CLIENT_ID)->first();
        if ($userId === '' || $agent === null) {
            return redirect('/')->with('delegation_flash', ['step' => 'preview', 'ok' => false, 'detail' => 'Run setup first.']);
        }

        $preview = app(ConsentPreview::class)->forGrant(
            new SubjectRef('user', $userId),
            $agent->subject(),
            ['owner', 'viewer'],
        );

        $lines = [];
        foreach ($preview['relations'] as $relation) {
            $lines[] = $relation['relation'].': '.$relation['total'].' resource(s)'
                .($relation['truncated'] ? ' (showing '.count($relation['resources']).')' : '')
                .($relation['resources'] === [] ? '' : ' — '.implode(', ', $relation['resources']));
        }

        return redirect('/')->with('delegation_flash', [
            'step' => 'preview', 'ok' => true,
            'detail' => ($lines === [] ? 'No overlap on the previewed relations' : implode(' · ', $lines))
                .' — this is the INTERSECTION of what the user reaches and what the agent reaches, not the scope name.',
        ]);
    }

    /**
     * Step 4c — MULTI-HOP: agent A, already acting for the user, hands the work to agent B.
     *
     * Two things this proves and a flat description cannot: the `act` claim NESTS (B outermost,
     * A inside), and the authority only NARROWS — B holds no permission of its own, so the
     * intersection user ∩ A ∩ B denies what A alone was allowed. That second half is the whole
     * reason multi-hop is safe: a longer chain can never buy authority.
     */
    public function chain(Request $request): RedirectResponse
    {
        $userId = (string) Auth::id();
        $token = $request->session()->get('delegation_demo.token');
        if ($userId === '' || ! is_array($token)) {
            return redirect('/')->with('delegation_flash', ['step' => 'chain', 'ok' => false, 'detail' => 'Run the exchange first.']);
        }

        // Depth 2 for this walkthrough only. The package default is 1: multi-hop is correct by
        // construction but widens accountability (whoever authorised B is A, not the user), so an
        // installation should switch it on deliberately.
        config()->set('iam-agents.max_delegation_depth', 2);
        app()->forgetInstance(AuthorizationServer::class);

        $secret = Str::random(32);
        $client = OauthClient::query()->updateOrCreate(
            ['client_id' => self::HOP2_CLIENT_ID],
            [
                'name' => self::HOP2_NAME,
                'redirect_uris' => [],
                'grants' => [ActClaim::GRANT_TYPE_TOKEN_EXCHANGE],
                'scopes' => ['invoices.view'],
                'is_confidential' => true,
            ],
        );
        $client->secret = Hash::make($secret);
        $client->save();

        $hop2 = Agent::query()->firstOrCreate(
            ['client_id' => self::HOP2_CLIENT_ID],
            [
                'id' => Agent::newId(),
                'name' => self::HOP2_NAME,
                'operator' => 'demo',
                'max_scopes' => ['invoices.view'],
                'status' => AgentStatus::Active->value,
            ],
        );
        // Deliberately NO PDP grant for hop 2: it is the denying link that proves the intersection.

        $sub = SymfonyRequest::create(route('iam.oauth.token'), 'POST', [
            'grant_type' => ActClaim::GRANT_TYPE_TOKEN_EXCHANGE,
            'client_id' => self::HOP2_CLIENT_ID,
            'client_secret' => $secret,
            'subject_token' => $token['jwt'],
            'subject_token_type' => ActClaim::TOKEN_TYPE_ACCESS,
        ]);
        $response = app()->handle($sub);
        $body = json_decode((string) $response->getContent(), true) ?: [];

        if ($response->getStatusCode() !== 200) {
            return redirect('/')->with('delegation_flash', [
                'step' => 'chain', 'ok' => false,
                'detail' => 'Chained exchange REFUSED — '.($body['error'] ?? 'error').' (reason in the delegation audit stream).',
            ]);
        }

        $claims = app(TokenSigner::class)->parse($body['access_token']);
        $agentA = Agent::query()->where('client_id', self::AGENT_CLIENT_ID)->first();

        // The same permission A was allowed, now asked for the WHOLE chain.
        $decision = app(DelegatedAuthorizationEngine::class)->checkDelegated(
            new SubjectRef('user', $userId),
            new DelegationChain(ActorRef::fromAgentId($hop2->id), ActorRef::fromAgentId((string) $agentA?->id)),
            ['permission' => 'invoices.view'],
        );

        return redirect('/')->with('delegation_flash', [
            'step' => 'chain', 'ok' => true,
            'detail' => 'act='.json_encode($claims['act'] ?? null).' (B outermost, A nested) · sub still='.($claims['sub'] ?? '?')
                .' · grant still the ROOT one='.($claims['pds_dgr'] ?? '?')
                .' — and invoices.view now ⇒ '.((($decision['allowed'] ?? false)) ? 'ALLOW' : 'DENY')
                .': hop 2 holds no permission, so the chain NARROWS what hop 1 could do. A longer chain never buys authority.',
        ]);
    }

    /**
     * Step 5 — revoke, then watch the next exchange fail. Uses the module's own store (the same
     * path the self-service DELETE and the console kill-switch go through), so the revocation is
     * audited with who revoked.
     */
    /**
     * Step 4d — ACCESS REVIEW: la delega finisce in una campagna di certificazione.
     *
     * Il punto che una descrizione non rende: una delega dimenticata è INVISIBILE. Un ruolo dato a
     * una persona prima o poi salta fuori perché la persona cambia team o se ne va; un agente non ha
     * un evento di ciclo di vita equivalente. Questa campagna la tira fuori, con addosso i segnali
     * che dicono al reviewer se serve ancora — e la revoca del reviewer è una revoca vera, che passa
     * dallo store e fa fallire l'exchange successivo esattamente come il pulsante "Revoke".
     */
    public function review(Request $request): RedirectResponse
    {
        $userId = (string) Auth::id();
        $grant = DelegationGrantModel::query()
            ->where('user_id', $userId)
            ->where('status', DelegationGrantStatus::Active->value)
            ->first();
        if ($userId === '' || $grant === null) {
            return redirect('/')->with('delegation_flash', ['step' => 'review', 'ok' => false, 'detail' => 'Run setup + consent first: there is no active delegation to certify.']);
        }

        // `reviewable_types` ESPLICITO: senza, la campagna certifica solo i grant RBAC — installare
        // il modulo non fa comparire deleghe dentro campagne già pianificate.
        $campaign = ReviewCampaign::create([
            'name' => 'Demo — delegation certification',
            'on_unconfirmed' => 'revoke',
            'scope_json' => ['reviewable_types' => ['delegation_grant']],
        ]);

        $engine = app(CampaignEngine::class);
        $created = $engine->open($campaign);

        $item = ReviewItem::query()
            ->where('campaign_id', $campaign->id)
            ->where('reviewable_id', $grant->id)
            ->first();
        if ($item === null) {
            return redirect('/')->with('delegation_flash', ['step' => 'review', 'ok' => false, 'detail' => 'The campaign opened but did not pick up the delegation.']);
        }

        $signals = is_array($item->signals_json) ? $item->signals_json : [];
        $flags = [];
        foreach (['never_used', 'dormant', 'agent_suspended'] as $flag) {
            if (($signals[$flag] ?? false) === true) {
                $flags[] = str_replace('_', ' ', $flag);
            }
        }

        // Il reviewer revoca. Passa dallo store: audita ed emette DelegationGrantRevoked, quindi il
        // prossimo exchange fallisce — non è una decisione "sulla carta".
        $engine->decide($item, 'revoked', 'user:'.$userId, 'demo: certificata come non più necessaria');

        return redirect('/')->with('delegation_flash', [
            'step' => 'review', 'ok' => true,
            'detail' => "Campaign opened ({$created} item) · reviewer = {$item->reviewer_subject} (the delegating user)"
                .($flags === [] ? '' : ' · signals: '.implode(', ', $flags))
                ." · certified as REVOKED → grant status is now {$grant->fresh()?->status}."
                .' Try "Exchange" again: it fails, because the review revoked for real.',
        ]);
    }

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

        // The demo log tail: every [agent-api] line carries the iam_delegation Context the
        // middleware hydrated — the "an agent is acting, the sub is a user" evidence.
        $logTail = [];
        $logFile = storage_path('logs/laravel.log');
        if (is_file($logFile)) {
            $lines = array_filter(explode("\n", (string) file_get_contents($logFile)), fn (string $l): bool => str_contains($l, '[agent-api]'));
            $logTail = array_slice(array_values($lines), -3);
        }

        $tokenState = session('delegation_demo.token');
        if (is_array($tokenState)) {
            unset($tokenState['jwt']); // the raw token never reaches the browser
        }

        return [
            'agent' => $agent === null ? null : ['id' => $agent->id, 'name' => $agent->name, 'status' => $agent->status, 'max_scopes' => $agent->max_scopes],
            'grants' => $grants,
            'token' => $tokenState,
            'calls' => session('delegation_demo.calls'),
            'log_tail' => $logTail,
            'audit' => $audit,
            'stepup_code' => app()->environment('production') ? null : (string) env('DEMO_STEPUP_CODE', '123456'),
        ];
    }
}
