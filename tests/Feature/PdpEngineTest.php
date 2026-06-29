<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Contracts\Authorization\AuthorizationEngine;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Authorization\Models\Permission;
use Padosoft\Iam\Domain\Authorization\Models\Role;
use Padosoft\Iam\Domain\Organizations\Models\Organization;
use Tests\TestCase;

/**
 * End-to-end proof of the Laravel IAM Policy Decision Point (NativeSqlEngine)
 * against the real Packagist-installed package. Every field/method is grounded
 * in vendor/padosoft/laravel-iam-server/src.
 */
class PdpEngineTest extends TestCase
{
    use RefreshDatabase;

    private function engine(): AuthorizationEngine
    {
        return app(AuthorizationEngine::class);
    }

    /** 1. No grant exists → fail-closed default-deny. */
    public function test_default_deny_when_no_grant(): void
    {
        $d = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'invoices.view',
            'explain' => true,
        ]);

        $this->assertFalse($d['allowed']);
        $this->assertSame([], $d['matched']);
        $this->assertNotEmpty($d['explanation']);
    }

    /** 2. Direct permission grant (privilege_type=permission) → allow. */
    public function test_direct_permission_grant_allows(): void
    {
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'u1',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices.view',
            'effect' => 'permit', 'valid_from' => now(),
        ]);

        $d = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'invoices.view',
            'explain' => true,
        ]);

        $this->assertTrue($d['allowed']);
        $this->assertSame([['type' => 'permission', 'key' => 'invoices.view']], $d['matched']);
    }

    /** 3. RBAC: role with attached permission, role granted to user → allow for that permission. */
    public function test_rbac_role_grant_resolves_permission(): void
    {
        $permission = Permission::query()->create([
            'app_key' => 'warehouse', 'key' => 'stock.adjust',
            'full_key' => 'warehouse:stock.adjust',
        ]);
        $role = Role::query()->create([
            'app_key' => 'warehouse', 'key' => 'stock_operator',
            'full_key' => 'warehouse:stock_operator',
        ]);
        // Pivot iam_role_permissions(role_id, permission_id) — verified in Role::permissions().
        $role->permissions()->attach($permission->id);

        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'u1',
            'privilege_type' => 'role', 'privilege_key' => 'warehouse:stock_operator',
            'effect' => 'permit', 'valid_from' => now(),
        ]);

        $d = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'warehouse:stock.adjust',
            'explain' => true,
        ]);

        $this->assertTrue($d['allowed']);
        $this->assertSame([['type' => 'role', 'key' => 'warehouse:stock_operator']], $d['matched']);

        // A permission NOT attached to the role is not authorized via this role grant.
        $other = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'warehouse:stock.delete',
        ]);
        $this->assertFalse($other['allowed']);
    }

    /** 4. deny-overrides: an explicit effect=deny grant beats a coexisting permit. */
    public function test_deny_overrides_permit(): void
    {
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'u1',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices.view',
            'effect' => 'permit', 'valid_from' => now(),
        ]);
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'u1',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices.view',
            'effect' => 'deny', 'valid_from' => now(),
        ]);

        $d = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'invoices.view',
            'explain' => true,
        ]);

        $this->assertFalse($d['allowed']);
        $this->assertSame([['type' => 'deny', 'key' => 'invoices.view']], $d['matched']);
    }

    /** 5. A permission grant for a Permission whose catalog row is deprecated_at → not granted. */
    public function test_deprecated_permission_is_not_granted(): void
    {
        Permission::query()->create([
            'app_key' => 'invoices', 'key' => 'view',
            'full_key' => 'invoices:view', 'deprecated_at' => now(),
        ]);
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'u1',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices:view',
            'effect' => 'permit', 'valid_from' => now(),
        ]);

        $d = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'invoices:view',
        ]);

        $this->assertFalse($d['allowed']);
    }

    /** 6. resource_ref scope: allows the matching resource, denies a different one. */
    public function test_resource_scope_matching(): void
    {
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'u1',
            'privilege_type' => 'permission', 'privilege_key' => 'docs.read',
            'resource_ref' => 'doc:1',
            'effect' => 'permit', 'valid_from' => now(),
        ]);

        $allow = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'docs.read', 'resource' => 'doc:1',
        ]);
        $this->assertTrue($allow['allowed']);

        $deny = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'docs.read', 'resource' => 'doc:2',
        ]);
        $this->assertFalse($deny['allowed']);
    }

    /** 7. ABAC conditions_json {field:{op:value}}: allow when context satisfies, deny otherwise. */
    public function test_abac_conditions(): void
    {
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'u1',
            'privilege_type' => 'permission', 'privilege_key' => 'reports.view',
            'conditions_json' => ['region' => ['=' => 'EU'], 'level' => ['>=' => 3]],
            'effect' => 'permit', 'valid_from' => now(),
        ]);

        $ok = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'reports.view',
            'context' => ['region' => 'EU', 'level' => 5],
        ]);
        $this->assertTrue($ok['allowed']);

        // Wrong region → condition fails → deny.
        $badRegion = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'reports.view',
            'context' => ['region' => 'US', 'level' => 5],
        ]);
        $this->assertFalse($badRegion['allowed']);

        // Missing context field → fail-closed deny.
        $missing = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'reports.view',
            'context' => ['region' => 'EU'],
        ]);
        $this->assertFalse($missing['allowed']);
    }

    /** 8a. Tenant isolation: an org-scoped grant must not authorize a check in another org. */
    public function test_tenant_isolation_by_organization(): void
    {
        $orgA = Organization::query()->create(['key' => 'org-a', 'name' => 'Org A']);
        $orgB = Organization::query()->create(['key' => 'org-b', 'name' => 'Org B']);

        Grant::query()->create([
            'organization_id' => $orgA->id,
            'subject_type' => 'user', 'subject_id' => 'u1',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices.view',
            'effect' => 'permit', 'valid_from' => now(),
        ]);

        $inA = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'invoices.view', 'organization' => $orgA->id,
        ]);
        $this->assertTrue($inA['allowed']);

        $inB = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'invoices.view', 'organization' => $orgB->id,
        ]);
        $this->assertFalse($inB['allowed']);
    }

    /** 8b. Application isolation: an app-scoped grant must not authorize a check for another app. */
    public function test_tenant_isolation_by_application(): void
    {
        Grant::query()->create([
            'application_key' => 'appA',
            'subject_type' => 'user', 'subject_id' => 'u1',
            'privilege_type' => 'permission', 'privilege_key' => 'invoices.view',
            'effect' => 'permit', 'valid_from' => now(),
        ]);

        $inApp = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'invoices.view', 'application' => 'appA',
        ]);
        $this->assertTrue($inApp['allowed']);

        $otherApp = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'invoices.view', 'application' => 'appB',
        ]);
        $this->assertFalse($otherApp['allowed']);
    }

    /** 9. step-up: requires_step_up permission permits at aal1 but flags step-up; satisfied at aal2. */
    public function test_step_up_required_at_aal1_satisfied_at_aal2(): void
    {
        Permission::query()->create([
            'app_key' => 'billing', 'key' => 'charge.create',
            'full_key' => 'billing:charge.create', 'requires_step_up' => true,
        ]);
        Grant::query()->create([
            'subject_type' => 'user', 'subject_id' => 'u1',
            'privilege_type' => 'permission', 'privilege_key' => 'billing:charge.create',
            'effect' => 'permit', 'valid_from' => now(),
        ]);

        $aal1 = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'billing:charge.create', 'current_aal' => 'aal1',
        ]);
        $this->assertTrue($aal1['allowed']);
        $this->assertTrue($aal1['requires_step_up']);
        $this->assertSame('aal2', $aal1['required_aal']);

        $aal2 = $this->engine()->check([
            'subject' => ['type' => 'user', 'id' => 'u1'],
            'permission' => 'billing:charge.create', 'current_aal' => 'aal2',
        ]);
        $this->assertTrue($aal2['allowed']);
        $this->assertFalse($aal2['requires_step_up']);
        $this->assertNull($aal2['required_aal']);
    }
}
