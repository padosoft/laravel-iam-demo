<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Contracts\Support\SubjectRef;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Governance\Requests\AccessRequestService;
use Padosoft\Iam\Domain\Governance\Requests\Models\AccessRequest;
use Tests\TestCase;

/**
 * End-to-end proof of the Grant lifecycle (time-boxing, revoke, PIM activation) and of the
 * self-service Access Request workflow (limited user requests a role → approve/reject). Everything
 * is asserted through the real PDP (AuthorizationEngine::check) against the Packagist-installed code.
 */
class GrantsAndRequestsTest extends TestCase
{
    use RefreshDatabase;

    private AuthorizationEngine $engine;

    protected function setUp(): void
    {
        parent::setUp();
        $this->engine = app(AuthorizationEngine::class);
    }

    /** PDP allow/deny helper for a permission full_key, optionally scoped to an application. */
    private function allows(string $subjectId, string $permission, ?string $application = null): bool
    {
        $query = ['subject' => ['type' => 'user', 'id' => $subjectId], 'permission' => $permission];
        if ($application !== null) {
            $query['application'] = $application;
        }

        return $this->engine->check($query)['allowed'];
    }

    // ---------------------------------------------------------------------------------------------
    // 1. Time-boxed grants: validity window is enforced by Grant::scopeActive (fail-closed).
    // ---------------------------------------------------------------------------------------------

    public function test_time_boxed_grant_window_is_enforced(): void
    {
        // Past window: valid_until already elapsed → NOT active → deny.
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'tb-past',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices.view',
            'effect' => 'permit',
            'valid_from' => now()->subDays(2), 'valid_until' => now()->subDay(),
        ]);
        $this->assertFalse($this->allows('tb-past', 'invoices.view'), 'expired grant must be denied');

        // Future window: valid_from not reached yet → NOT YET active → deny.
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'tb-future',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices.view',
            'effect' => 'permit',
            'valid_from' => now()->addDay(), 'valid_until' => now()->addDays(2),
        ]);
        $this->assertFalse($this->allows('tb-future', 'invoices.view'), 'not-yet-valid grant must be denied');

        // Current window: now is inside [valid_from, valid_until] → active → allow.
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'tb-now',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices.view',
            'effect' => 'permit',
            'valid_from' => now()->subDay(), 'valid_until' => now()->addDay(),
        ]);
        $this->assertTrue($this->allows('tb-now', 'invoices.view'), 'grant inside its window must be allowed');
    }

    // ---------------------------------------------------------------------------------------------
    // 2. revoke(): an active permit becomes inert the moment it is revoked.
    // ---------------------------------------------------------------------------------------------

    public function test_revoke_makes_an_active_grant_deny(): void
    {
        $grant = Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'rev-1',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices.edit',
            'effect' => 'permit', 'valid_from' => now()->subHour(),
        ]);
        $this->assertTrue($this->allows('rev-1', 'invoices.edit'), 'fresh active grant must allow');

        $grant->revoke('user:admin');

        $this->assertNotNull($grant->fresh()->revoked_at, 'revoke() must stamp revoked_at');
        $this->assertSame('user:admin', $grant->fresh()->revoked_by);
        $this->assertFalse($this->allows('rev-1', 'invoices.edit'), 'revoked grant must be denied');
    }

    // ---------------------------------------------------------------------------------------------
    // 3. PIM: activation_required grants are inert until activate() (fail-closed).
    // ---------------------------------------------------------------------------------------------

    public function test_pim_grant_requires_activation_before_it_is_effective(): void
    {
        $grant = Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'pim-1',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices.delete',
            'effect' => 'permit', 'valid_from' => now()->subHour(),
            'activation_required' => true,
        ]);

        // Fail-closed: a PIM grant that has never been activated must NOT grant access.
        $this->assertNull($grant->activated_at);
        $this->assertFalse($this->allows('pim-1', 'invoices.delete'), 'un-activated PIM grant must be denied');

        $grant->activate();

        $this->assertNotNull($grant->fresh()->activated_at, 'activate() must stamp activated_at');
        $this->assertTrue($this->allows('pim-1', 'invoices.delete'), 'activated PIM grant must be allowed');
    }

    // ---------------------------------------------------------------------------------------------
    // Shared fixture for the Access Request scenarios: a self-requestable role that carries a target
    // permission, the governance feature switched on, and the requester holding the catalog "use" gate.
    // ---------------------------------------------------------------------------------------------

    private const TARGET_PERMISSION = 'invoices:reports.approve';

    private const ROLE_KEY = 'invoices:approver';

    private function seedRequestableRole(): Role
    {
        $role = Role::query()->create([
            'app_key' => 'invoices', 'key' => 'approver', 'full_key' => self::ROLE_KEY,
            'label' => 'Invoice Approver', 'self_requestable' => true,
            'request_json' => [
                'visibility' => ['policy' => 'public'],
                'approvers' => ['user:boss'],
                'max_duration' => 'P7D',
            ],
        ]);

        $permission = Permission::query()->create([
            'app_key' => 'invoices', 'key' => 'reports.approve', 'full_key' => self::TARGET_PERMISSION,
        ]);
        $role->permissions()->attach($permission->id);

        return $role;
    }

    /** Give a limited user the catalog "use" gate (iam:access_request.use) as a global permit grant. */
    private function grantCatalogUse(string $subjectId): void
    {
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => $subjectId,
            'privilege_type' => 'permission', 'privilege_key' => 'iam:access_request.use',
            'effect' => 'permit', 'valid_from' => now()->subHour(),
        ]);
    }

    /** Enable the access_request feature (privacy-by-default ships it off). */
    private function enableAccessRequestFeature(): void
    {
        config(['iam-governance.features.access_request.default' => 'on']);
    }

    // ---------------------------------------------------------------------------------------------
    // 4. Access Request — happy path: limited user requests a role, gets approved, PDP then allows.
    // ---------------------------------------------------------------------------------------------

    public function test_access_request_happy_path_grants_access_on_approval(): void
    {
        $this->enableAccessRequestFeature();
        $this->seedRequestableRole();

        $requester = new SubjectRef('user', 'req-100');
        $this->grantCatalogUse($requester->id);

        // Before any request, the limited user has NO access to the target permission.
        $this->assertFalse(
            $this->allows($requester->id, self::TARGET_PERMISSION, 'invoices'),
            'requester must start with no access'
        );

        /** @var AccessRequestService $service */
        $service = app(AccessRequestService::class);

        // Self-service submit through the real catalog gate.
        $request = $service->submit($requester, self::ROLE_KEY, 'Need to approve invoices for Q3');
        $this->assertInstanceOf(AccessRequest::class, $request);
        $this->assertSame('pending', $request->status);

        // Approval by a distinct approver (segregation of duties) materialises a time-boxed grant.
        $grant = $service->approve($request, 'user:boss');

        $this->assertInstanceOf(Grant::class, $grant);
        $this->assertSame('access_request', $grant->source);
        $this->assertSame('role', $grant->privilege_type);
        $this->assertSame(self::ROLE_KEY, $grant->privilege_key);
        $this->assertNotNull($grant->valid_until, 'approved grant must be time-boxed (max_duration P7D)');

        // The request is now approved and linked to the grant.
        $request->refresh();
        $this->assertSame('approved', $request->status);
        $this->assertSame($grant->id, $request->granted_grant_id);

        // A persisted grant now exists for the requester, and the PDP ALLOWS the role's permission.
        $this->assertTrue(
            Grant::query()->where('subject_id', $requester->id)
                ->where('privilege_key', self::ROLE_KEY)->where('source', 'access_request')->exists(),
            'an access-request grant must now exist for the requester'
        );
        $this->assertTrue(
            $this->allows($requester->id, self::TARGET_PERMISSION, 'invoices'),
            'after approval the PDP must allow the role-derived permission'
        );
    }

    // ---------------------------------------------------------------------------------------------
    // 5. Access Request — reject path: no grant is created, PDP keeps denying.
    // ---------------------------------------------------------------------------------------------

    public function test_access_request_reject_path_creates_no_grant(): void
    {
        $this->enableAccessRequestFeature();
        $this->seedRequestableRole();

        $requester = new SubjectRef('user', 'req-200');
        $this->grantCatalogUse($requester->id);

        /** @var AccessRequestService $service */
        $service = app(AccessRequestService::class);
        $request = $service->submit($requester, self::ROLE_KEY, 'Please grant me approver');

        $service->reject($request, 'user:boss', 'Not justified enough');

        $request->refresh();
        $this->assertSame('rejected', $request->status);
        $this->assertNull($request->granted_grant_id, 'a rejected request must not link any grant');
        $this->assertFalse(
            Grant::query()->where('subject_id', $requester->id)->where('privilege_key', self::ROLE_KEY)->exists(),
            'a rejected request must create no grant'
        );
        $this->assertFalse(
            $this->allows($requester->id, self::TARGET_PERMISSION, 'invoices'),
            'after rejection the PDP must still deny'
        );
    }

    // ---------------------------------------------------------------------------------------------
    // 6. Catalog default-deny: only self_requestable roles in the catalog can be requested.
    // ---------------------------------------------------------------------------------------------

    public function test_catalog_refuses_off_catalog_privileges(): void
    {
        $this->enableAccessRequestFeature();
        $this->seedRequestableRole();

        $requester = new SubjectRef('user', 'req-300');
        $this->grantCatalogUse($requester->id);

        // A role that exists but is NOT marked self_requestable must be refused by the catalog.
        Role::query()->create([
            'app_key' => 'invoices', 'key' => 'superadmin', 'full_key' => 'invoices:superadmin',
            'label' => 'Super Admin', 'self_requestable' => false,
        ]);

        /** @var AccessRequestService $service */
        $service = app(AccessRequestService::class);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('non richiedibile');
        $service->submit($requester, 'invoices:superadmin', 'I want admin');
    }

    /** A privilege key that is not in the catalog at all is likewise refused (same opaque message). */
    public function test_catalog_refuses_unknown_privileges(): void
    {
        $this->enableAccessRequestFeature();
        $requester = new SubjectRef('user', 'req-301');
        $this->grantCatalogUse($requester->id);

        /** @var AccessRequestService $service */
        $service = app(AccessRequestService::class);

        $this->expectException(\RuntimeException::class);
        $service->submit($requester, 'invoices:does-not-exist', 'anything');
    }
}
