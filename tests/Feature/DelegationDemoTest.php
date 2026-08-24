<?php

namespace Tests\Feature;

use App\Http\Controllers\DelegationDemoController;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;
use Padosoft\Iam\Agents\Models\Agent;
use Padosoft\Iam\Agents\Models\DelegationGrantModel;
use Padosoft\Iam\Contracts\Crypto\TokenSigner;
use Padosoft\Iam\Contracts\Identity\SessionRegistry;
use Padosoft\Iam\Domain\Audit\Models\AuditEvent;
use Tests\TestCase;

/**
 * THE acceptance test of the delegated-access plan (§7.6): register agent → user consents (real
 * step-up-bound consent via the module's self-service endpoints) → RFC 8693 exchange on the real
 * token endpoint → intersection allows/denies → audit carries both identities → revoke → the next
 * exchange fails. All in-process, no mocks — the same loop the dashboard panel walks by hand.
 */
class DelegationDemoTest extends TestCase
{
    use RefreshDatabase;

    /** @var array{agent_id: string, scopes: list<string>, ttl_seconds: int, purpose: string} */
    private array $consentPayload;

    private function loginAndSetup(): Agent
    {
        $this->get('/')->assertOk(); // seeds demo@example.com + its invoices.view/create grants
        $this->post('/demo/login', ['email' => 'demo@example.com', 'password' => 'password'])->assertRedirect('/');
        $this->assertIsString(session('iam_sid'), 'login must start a real IAM session');

        $this->post(route('demo.delegation.setup'))->assertRedirect('/');
        $agent = Agent::query()->where('client_id', DelegationDemoController::AGENT_CLIENT_ID)->firstOrFail();

        $this->consentPayload = [
            'agent_id' => $agent->id,
            'scopes' => ['invoices.view'],
            'ttl_seconds' => 86400,
            'purpose' => 'Read my invoices for the weekly digest',
        ];

        return $agent;
    }

    /** @param array<string, mixed> $overrides */
    private function consent(array $overrides = [], string $code = '123456'): TestResponse
    {
        $challenge = $this->postJson('/iam/me/delegations/consent-challenge', $this->consentPayload)
            ->assertOk()->json('data');

        return $this->postJson('/iam/me/delegations', array_merge(
            $this->consentPayload,
            ['challenge_id' => $challenge['challenge_id'], 'verification' => ['code' => $code]],
            $overrides,
        ));
    }

    public function test_the_full_delegation_loop(): void
    {
        $agent = $this->loginAndSetup();

        // Consent: challenge bound to (agent, scopes, ttl, purpose), verified with the demo factor.
        $this->consent()->assertStatus(201);
        $grant = DelegationGrantModel::query()->where('agent_id', $agent->id)->firstOrFail();
        $this->assertSame('aal2', $grant->consent_aal, 'the grant must cite the consent evidence');
        $this->assertNotEmpty($grant->consent_confirmation_id);

        // Exchange on the REAL token endpoint: two identities in the delegated token.
        $this->post(route('demo.delegation.exchange'))->assertRedirect('/');
        $token = session('delegation_demo.token');
        $this->assertIsArray($token);
        $user = User::query()->where('email', 'demo@example.com')->firstOrFail();
        $this->assertSame((string) $user->getKey(), $token['claims']['sub'], 'sub stays the USER');
        $this->assertSame(['sub' => 'agent:'.$agent->id], $token['claims']['act'], 'act is the AGENT');
        $this->assertSame($grant->id, $token['claims']['pds_dgr'], 'the token cites the grant (targeted revocation)');
        $this->assertLessThanOrEqual(300, (int) $token['expires_in'], 'short TTL by design');

        // THE PROOF — the agent hits a REAL protected API (iam.can.delegated, mandatory
        // introspection, intersection): no token ⇒ 401; the delegated token reads invoices (in
        // the intersection) ⇒ 200 AND the response echoes the hydrated Laravel Context — an AGENT
        // is acting, the sub stays the USER; invoices.create (user holds it, agent doesn't) ⇒ 403.
        $jwt = $token['jwt'];
        $this->getJson('/demo/agent-api/invoices')->assertStatus(401);
        $this->withToken($jwt)->getJson('/demo/agent-api/invoices')
            ->assertOk()
            ->assertJsonPath('iam_delegation.sub', (string) $user->getKey())
            ->assertJsonPath('iam_delegation.actors.0', 'agent:'.$agent->id)
            ->assertJsonPath('iam_delegation.grant_id', $grant->id);
        $this->withToken($jwt)->postJson('/demo/agent-api/invoices')->assertStatus(403);

        // A PLAIN user token (no act) is refused on the agent surface: 401, never a downgrade.
        $plainUserToken = app(TokenSigner::class)
            ->issue(['sub' => (string) $user->getKey(), 'sid' => (string) session('iam_sid'), 'aud' => 'cli_demo', 'scope' => 'openid'], 900);
        $this->withToken($plainUserToken)->getJson('/demo/agent-api/invoices')->assertStatus(401);

        // The orchestrator-side walkthrough button reports the same three outcomes.
        $this->post(route('demo.delegation.call'))->assertRedirect('/');
        $this->assertTrue(session('delegation_flash')['ok'], 'call step must see 401/200/403');

        // Intersection: view passes both layers; create is DENIED although the USER holds it.
        $this->post(route('demo.delegation.check'))->assertRedirect('/');
        $flash = session('delegation_flash');
        $this->assertStringContainsString('invoices.view ⇒ ALLOW', $flash['detail']);
        $this->assertStringContainsString('invoices.create ⇒ DENY', $flash['detail']);

        // Audit: the exchange is on stream=delegation with BOTH identities in the metadata.
        $issued = AuditEvent::query()->where('stream', 'delegation')
            ->where('event_type', 'iam.delegation.exchange.issued')->latest('id')->first();
        $this->assertNotNull($issued);
        $this->assertSame($agent->id, $issued->actor_agent_id, 'the acting AGENT is on the event');
        $this->assertSame((string) $user->getKey(), $issued->metadata_json['user'] ?? null, 'the delegating USER is on the event');
        $this->assertSame($grant->id, $issued->metadata_json['grant_id'] ?? null);

        // Revoke → the NEXT exchange fails: revocation lands at the next check, not at expiry.
        $this->post(route('demo.delegation.revoke'))->assertRedirect('/');
        $this->post(route('demo.delegation.exchange'))->assertRedirect('/');
        $flash = session('delegation_flash');
        $this->assertFalse($flash['ok']);
        $this->assertStringContainsString('invalid_grant', $flash['detail']);
        $this->assertNull(session('delegation_demo.token'), 'no delegated token survives the refusal');
    }

    public function test_consent_is_dynamically_linked_and_needs_the_right_factor(): void
    {
        $this->loginAndSetup();

        // Parameters changed AFTER the challenge screen ⇒ binding mismatch ⇒ refused.
        $this->consent(['scopes' => ['invoices.view', 'invoices.create']])->assertStatus(422);

        // Wrong step-up code ⇒ refused, no grant created.
        $this->consent(code: '000000')->assertStatus(422);
        $this->assertSame(0, DelegationGrantModel::query()->count());
    }

    public function test_a_dead_user_session_kills_the_next_exchange(): void
    {
        $this->loginAndSetup();
        $this->consent()->assertStatus(201);
        $this->post(route('demo.delegation.exchange'))->assertRedirect('/');
        $this->assertTrue(session('delegation_flash')['ok']);

        // The user's IAM session is revoked elsewhere (console kill-switch, logout on another device):
        // the very next exchange refuses — the re-exchange IS the freshness check.
        app(SessionRegistry::class)->revokeSession((string) session('iam_sid'), 'test-revoke');

        $this->post(route('demo.delegation.exchange'))->assertRedirect('/');
        $flash = session('delegation_flash');
        $this->assertFalse($flash['ok']);
        $this->assertStringContainsString('invalid_grant', $flash['detail']);
    }
}
