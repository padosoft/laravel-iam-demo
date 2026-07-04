<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Domain\OAuth\Models\OauthClient;
use Tests\TestCase;

/**
 * The interactive demo flow: onboard THIS app into IAM (manifest → OAuth client + one-time secret), then
 * log in against the IAM user store and read back the grants the PDP decides. All in-process, no mocks.
 */
class DemoFlowTest extends TestCase
{
    use RefreshDatabase;

    public function test_register_applies_the_manifest_and_mints_a_client_with_a_one_time_secret(): void
    {
        $this->post('/demo/register')->assertRedirect('/');

        $reg = session('registered');
        $this->assertIsArray($reg);
        $this->assertSame('cli_demo', $reg['client_id']);
        $this->assertNotEmpty($reg['client_secret'], 'apply must surface the one-time client secret');

        $client = OauthClient::query()->where('application_key', 'demo')->first();
        $this->assertNotNull($client, 'apply must register the OAuth client');
        $this->assertTrue((bool) $client->is_confidential);
        // auth.auto_rotate from the manifest is honoured.
        $this->assertTrue((bool) $client->auto_rotate);
    }

    public function test_login_authenticates_against_iam_and_the_dashboard_shows_decided_grants(): void
    {
        // Visiting home seeds the demo operator (demo@example.com / password) + its grants, idempotently.
        $this->get('/')->assertOk();
        $user = User::query()->where('email', 'demo@example.com')->firstOrFail();

        $this->post('/demo/login', ['email' => 'demo@example.com', 'password' => 'password'])
            ->assertRedirect('/');
        $this->assertAuthenticatedAs($user);

        // The dashboard renders the "your grants" panel from real PDP checks (view/create granted).
        $html = (string) $this->get('/')->assertOk()->getContent();
        $this->assertStringContainsString('my-grant', $html);
        $this->assertStringContainsString('invoices.view', $html);
    }

    public function test_login_rejects_bad_credentials(): void
    {
        $this->get('/'); // seed the demo operator
        $this->post('/demo/login', ['email' => 'demo@example.com', 'password' => 'nope'])
            ->assertRedirect('/');
        $this->assertGuest();
    }
}
