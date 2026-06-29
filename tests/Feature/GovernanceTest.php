<?php

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Governance\FeatureContext;
use Padosoft\Iam\Contracts\Governance\FeatureKey;
use Padosoft\Iam\Contracts\Governance\FeatureScope;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Governance\Recommendations\LeastPrivilegeRecommender;
use Padosoft\Iam\Domain\Governance\Reviews\CampaignEngine;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewCampaign;
use Padosoft\Iam\Domain\Governance\Reviews\Models\ReviewItem;
use Tests\TestCase;

/**
 * Feature tests for the Laravel IAM governance / IGA layer (doc 14): Access Review certification
 * campaigns, the FeatureScope cascade (layer→app→role→user) and the deterministic least-privilege /
 * anomaly recommender. Everything is grounded in vendor/padosoft/laravel-iam-server source — no mocks.
 */
class GovernanceTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Access Review campaign end-to-end (CampaignEngine + iam:reviews:open|close):
     * open generates one ReviewItem per active grant in scope; a reviewer certifies one grant and
     * revokes another; closing auto-revokes the still-pending (non-confirmed) grant per on_unconfirmed.
     */
    public function test_access_review_campaign_certify_revoke_and_auto_revoke_on_close(): void
    {
        $engine = app(CampaignEngine::class);

        // Three active, global grants (organization_id null) so a global campaign certifies them all.
        $grantKeep = $this->grant('user', 'alice', 'invoices.view');
        $grantRevoke = $this->grant('user', 'bob', 'invoices.delete');
        $grantPending = $this->grant('user', 'carol', 'invoices.export');

        // Global campaign with empty scope = full inventory; default on_unconfirmed = 'revoke'.
        $campaign = ReviewCampaign::query()->create([
            'name' => 'Q2 certification',
            'reviewer_strategy' => 'named',
            'scope_json' => ['reviewer' => 'user:auditor'],
            'on_unconfirmed' => 'revoke',
        ]);

        // Open via the real CLI command (iam:reviews:open) → items generated, campaign running.
        $this->artisan('iam:reviews:open', ['--campaign' => $campaign->id])->assertExitCode(0);

        $campaign->refresh();
        $this->assertSame('running', $campaign->status);
        $this->assertNotNull($campaign->opened_at);
        $this->assertSame(3, $campaign->items()->count(), 'one item per active grant in scope');

        // Each item carries the immutable smart-signals snapshot + the named reviewer.
        $itemKeep = $this->itemFor($campaign, $grantKeep);
        $itemRevoke = $this->itemFor($campaign, $grantRevoke);
        $itemPending = $this->itemFor($campaign, $grantPending);
        $this->assertSame('pending', $itemKeep->decision);
        $this->assertSame('user:auditor', $itemKeep->reviewer_subject);
        $this->assertIsArray($itemKeep->signals_json);
        $this->assertArrayHasKey('never_used', $itemKeep->signals_json);

        // Reviewer decisions: certify one (approved → grant kept), revoke another (grant removed now).
        $engine->decide($itemKeep, 'approved', 'user:auditor');
        $engine->decide($itemRevoke, 'revoked', 'user:auditor', 'no longer needed');

        $this->assertSame('approved', $itemKeep->fresh()->decision);
        $this->assertSame('revoked', $itemRevoke->fresh()->decision);
        $this->assertNotNull($grantRevoke->fresh()->revoked_at, 'reviewer-revoked grant is revoked immediately');
        $this->assertNull($grantKeep->fresh()->revoked_at, 'certified grant stays active');

        // itemPending is left untouched → close() applies on_unconfirmed=revoke (auto-revoke).
        $this->artisan('iam:reviews:close', ['--campaign' => $campaign->id])->assertExitCode(0);

        $campaign->refresh();
        $this->assertSame('completed', $campaign->status);
        $this->assertNotNull($campaign->closed_at);

        // The non-confirmed grant was auto-revoked; the certified one is still active.
        $itemPending->refresh();
        $this->assertSame('revoked', $itemPending->decision);
        $this->assertSame('system:access-review', $itemPending->decided_by);
        $this->assertNotNull($grantPending->fresh()->revoked_at, 'unconfirmed grant auto-revoked on close');
        $this->assertNull($grantKeep->fresh()->revoked_at, 'certified grant survives campaign close');

        // The auto-revoked grant no longer counts as active (PDP fail-closed surface).
        $this->assertFalse(
            Grant::query()->active()->whereKey($grantPending->id)->exists(),
            'auto-revoked grant drops out of the active set used by the PDP',
        );
        $this->assertTrue(Grant::query()->active()->whereKey($grantKeep->id)->exists());
    }

    /**
     * FeatureScope cascade (NativeFeatureScope, doc 14 §1): the most specific EXPLICIT level wins
     * (user > role > app > default), the safe default applies when unset, and isPermitted() gates on
     * the PDP permission.
     */
    public function test_feature_scope_cascade_resolves_most_specific_and_defaults_off(): void
    {
        /** @var FeatureScope $scope */
        $scope = app(FeatureScope::class);

        // Safe default: PIM ships 'off' → disabled when nothing is configured for the context.
        config()->set('iam-governance.features.pim', ['default' => 'off']);
        $this->assertFalse(
            $scope->isEnabled(new FeatureContext(FeatureKey::Pim)),
            'unset feature falls back to the safe default (off)',
        );

        // App level turns it on for application "billing".
        config()->set('iam-governance.features.pim', [
            'default' => 'off',
            'apps' => ['billing' => ['enabled' => 'on']],
            'roles' => ['billing.admin' => ['enabled' => 'off']],
            'users' => ['user:42' => ['enabled' => 'on']],
        ]);

        // app explicit 'on' beats the default 'off'.
        $this->assertTrue($scope->isEnabled(new FeatureContext(
            feature: FeatureKey::Pim,
            applicationKey: 'billing',
        )));

        // role explicit 'off' is more specific than the app 'on' → wins (off).
        $this->assertFalse($scope->isEnabled(new FeatureContext(
            feature: FeatureKey::Pim,
            applicationKey: 'billing',
            roleKey: 'billing.admin',
        )));

        // user explicit 'on' is the most specific → wins over the role 'off'.
        $this->assertTrue($scope->isEnabled(new FeatureContext(
            feature: FeatureKey::Pim,
            applicationKey: 'billing',
            roleKey: 'billing.admin',
            subject: new SubjectRef('user', '42'),
        )));

        // A different app with no explicit level falls back to the default 'off'.
        $this->assertFalse($scope->isEnabled(new FeatureContext(
            feature: FeatureKey::Pim,
            applicationKey: 'warehouse',
        )));

        // isPermitted(): the configured permission is evaluated by the PDP (fail-closed).
        config()->set('iam-governance.features.pim', [
            'default' => 'on',
            'permission' => 'pim.activate',
        ]);
        $ctx = new FeatureContext(FeatureKey::Pim);
        $actor = new SubjectRef('user', '777');

        $this->assertFalse(
            $scope->isPermitted($ctx, $actor),
            'no grant for the gate permission → not permitted (default-deny)',
        );

        $this->grant('user', '777', 'pim.activate');
        $this->assertTrue(
            $scope->isPermitted($ctx, $actor),
            'granting the gate permission lets the PDP permit the feature',
        );

        // With no permission gate configured the feature is permitted to anyone.
        config()->set('iam-governance.features.pim', ['default' => 'on']);
        $this->assertTrue($scope->isPermitted(new FeatureContext(FeatureKey::Pim), new SubjectRef('user', 'nobody')));
    }

    /**
     * Least-privilege / anomaly recommender (LeastPrivilegeRecommender + iam:least-privilege:scan):
     * deterministic rules produce DRAFT recommendations and the recommender mutates nothing.
     */
    public function test_least_privilege_recommender_produces_draft_recommendations_only(): void
    {
        // direct_permission: a direct permission grant (governance-by-role candidate).
        $direct = $this->grant('user', 'dave', 'reports.read'); // privilege_type 'permission'

        // permanent_privileged: privileged grant with no expiry (PIM/JIT candidate).
        $privileged = $this->grant('user', 'erin', 'admin.super', [
            'is_privileged' => true,
            'valid_until' => null,
        ]);

        // unused_grant: never used and created well past the 90-day threshold (revoke candidate).
        $unused = $this->grant('user', 'frank', 'legacy.access');
        Grant::query()->whereKey($unused->id)->update(['created_at' => now()->subDays(200)]);

        $recommender = app(LeastPrivilegeRecommender::class);
        $recommendations = $recommender->analyze();

        $this->assertNotEmpty($recommendations, 'seeded grants trigger deterministic rules');

        $types = array_map(static fn ($r) => $r->type, $recommendations);
        $this->assertContains('direct_permission', $types);
        $this->assertContains('permanent_privileged', $types);
        $this->assertContains('unused_grant', $types);

        // Every recommendation is a draft proposal (carries an action + human-readable detail).
        foreach ($recommendations as $rec) {
            $this->assertNotSame('', $rec->recommendation);
            $this->assertNotSame('', $rec->detail);
            $this->assertContains($rec->severity, ['low', 'medium', 'high']);
        }

        // The unused-grant finding proposes revoke and points at the right grant.
        $unusedRec = collect($recommendations)->first(
            static fn ($r) => $r->type === 'unused_grant' && $r->targetRef === $unused->id,
        );
        $this->assertNotNull($unusedRec);
        $this->assertSame('revoke', $unusedRec->recommendation);

        // Draft-only: NOTHING was mutated — every seeded grant is still active.
        $this->assertNull($direct->fresh()->revoked_at);
        $this->assertNull($privileged->fresh()->revoked_at);
        $this->assertNull($unused->fresh()->revoked_at);
        $this->assertSame(3, Grant::query()->active()->count(), 'recommender applies nothing automatically');

        // The CLI path (iam:least-privilege:scan --json) runs the same analysis successfully.
        $this->artisan('iam:least-privilege:scan', ['--json' => true])->assertExitCode(0);
    }

    /**
     * Creates an active permit grant. Defaults to a direct 'permission' privilege so it surfaces in
     * both the PDP and the recommender; callers override is_privileged/valid_until as needed.
     *
     * @param  array<string, mixed>  $overrides
     */
    private function grant(string $subjectType, string $subjectId, string $privilegeKey, array $overrides = []): Grant
    {
        return Grant::query()->create(array_merge([
            'subject_type' => $subjectType,
            'subject_id' => $subjectId,
            'privilege_type' => 'permission',
            'privilege_key' => $privilegeKey,
            'effect' => 'permit',
            'valid_from' => now(),
        ], $overrides));
    }

    private function itemFor(ReviewCampaign $campaign, Grant $grant): ReviewItem
    {
        $item = $campaign->items()->where('grant_id', $grant->id)->first();
        $this->assertNotNull($item, "review item generated for grant {$grant->id}");

        return $item;
    }
}
