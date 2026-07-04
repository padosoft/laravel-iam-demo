<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Padosoft\Iam\Directory\Contracts\DirectoryConnector;
use Padosoft\Iam\Directory\DirectoryAuthenticator;
use Padosoft\Iam\Directory\DirectoryJitPolicy;
use Padosoft\Iam\Directory\DirectoryProvisioner;
use Padosoft\Iam\Directory\DirectoryUser;
use Padosoft\Iam\Directory\GroupMapper;
use Padosoft\Iam\Domain\Authorization\Models\Grant;
use Padosoft\Iam\Domain\Identity\Models\User;
use Padosoft\Iam\Domain\Organizations\Models\Membership;
use Padosoft\Iam\Domain\Organizations\Models\Organization;
use Tests\TestCase;

/**
 * Feature tests for the Laravel IAM Directory module: group mapping, JIT provisioning, and the
 * security hardening (anti-takeover, protected_roles, stale-grant revocation, fail-closed auth).
 *
 * The provisioner writes into the SERVER tables (iam_users / iam_memberships / iam_grants), created
 * by the laravel-iam-server migrations under RefreshDatabase. No ext-ldap: a fake in-memory
 * DirectoryConnector implements the public contract.
 */
class DirectoryTest extends TestCase
{
    use RefreshDatabase;

    private function org(string $key = 'acme'): Organization
    {
        return Organization::query()->create(['key' => $key, 'name' => 'Acme Inc']);
    }

    /** Active (non-revoked) directory role grants held by a user in an org. */
    private function activeRoleKeys(string $orgId, string $userId, ?string $source = null): array
    {
        $keys = Grant::query()
            ->where('organization_id', $orgId)
            ->where('subject_type', 'user')
            ->where('subject_id', $userId)
            ->where('privilege_type', 'role')
            ->whereNull('revoked_at')
            ->when($source !== null, fn ($q) => $q->where('source', $source))
            ->pluck('privilege_key')
            ->all();
        sort($keys);

        return $keys;
    }

    // ── 1. GroupMapper: DN + short-CN, case-insensitive, default-deny ────────────────────

    public function test_group_mapper_maps_dn_and_short_cn_case_insensitively_and_denies_unmapped(): void
    {
        $mapper = new GroupMapper([
            'cn=admins,ou=groups,dc=acme,dc=com' => 'app.admin',   // full DN key
            'developers' => ['app.dev', 'app.deploy'],             // short CN key (list)
        ]);

        // Full DN match, case-insensitive on the input DN.
        $this->assertSame(['app.admin'], $mapper->rolesFor(['CN=Admins,OU=Groups,DC=acme,DC=com']));

        // A DN input matches a short-CN map entry via the extracted CN ("developers").
        $this->assertSame(['app.deploy', 'app.dev'], $mapper->rolesFor(['cn=Developers,ou=g,dc=x']));

        // Direct short-name input, case-insensitive.
        $this->assertSame(['app.deploy', 'app.dev'], $mapper->rolesFor(['DEVELOPERS']));

        // Unmapped group → no role (default-deny, no implicit roles).
        $this->assertSame([], $mapper->rolesFor(['cn=guests,ou=groups,dc=acme,dc=com']));
    }

    // ── 2. JIT provisioning of a brand-new directory user ────────────────────────────────

    public function test_jit_provisions_new_user_with_membership_and_directory_grants(): void
    {
        $org = $this->org();
        $policy = DirectoryJitPolicy::fromArray(['default_roles' => ['app.member']]);
        $user = new DirectoryUser(
            username: 'alice',
            email: 'Alice@acme.com',
            emailVerified: true,
            displayName: 'Alice',
            groups: [],
        );

        $outcome = (new DirectoryProvisioner)->provision($user, $policy, $org->id, []);

        $this->assertSame('provisioned', $outcome->status);
        $this->assertTrue($outcome->ok());
        $this->assertNotNull($outcome->userId);

        // User row created with normalized (lowercased) email and verified timestamp.
        $created = User::query()->find($outcome->userId);
        $this->assertNotNull($created);
        $this->assertSame('alice@acme.com', $created->email);
        $this->assertNotNull($created->email_verified_at);

        // Membership created with source=directory.
        $membership = Membership::query()
            ->where('organization_id', $org->id)->where('user_id', $created->id)->first();
        $this->assertNotNull($membership);
        $this->assertSame('directory', $membership->source);

        // Default role granted, source=directory.
        $this->assertSame(['app.member'], $this->activeRoleKeys($org->id, $created->id, 'directory'));
        $this->assertSame(['app.member'], $outcome->roles);
    }

    // ── 3. group→role mapping is applied on provision ────────────────────────────────────

    public function test_group_to_role_mapping_is_applied_on_provision(): void
    {
        $org = $this->org();
        $mapper = new GroupMapper(['alpha' => 'app.a', 'beta' => 'app.b']);
        $user = new DirectoryUser('bob', 'bob@acme.com', true, 'Bob', ['cn=alpha,ou=g,dc=x', 'beta']);

        $mappedRoles = $mapper->rolesFor($user->groups);
        $this->assertSame(['app.a', 'app.b'], $mappedRoles);

        $outcome = (new DirectoryProvisioner)->provision(
            $user, DirectoryJitPolicy::fromArray([]), $org->id, $mappedRoles
        );

        $this->assertSame('provisioned', $outcome->status);
        $this->assertSame(['app.a', 'app.b'], $this->activeRoleKeys($org->id, $outcome->userId, 'directory'));
    }

    // ── 4. anti-takeover: email owned by a NON-directory account → conflict, no takeover ──

    public function test_anti_takeover_email_owned_by_non_directory_account_yields_conflict(): void
    {
        $org = $this->org();

        // Pre-existing NON-directory account owning the email (e.g. a local/manual user).
        $local = User::query()->create([
            'email' => 'carol@acme.com', 'name' => 'Carol', 'email_verified_at' => now(),
        ]);
        Membership::query()->create([
            'organization_id' => $org->id, 'user_id' => $local->id, 'source' => 'manual', 'joined_at' => now(),
        ]);

        $dirUser = new DirectoryUser('carol', 'carol@acme.com', true, 'Carol', ['alpha']);
        $mapped = (new GroupMapper(['alpha' => 'app.a']))->rolesFor($dirUser->groups);

        $outcome = (new DirectoryProvisioner)->provision($dirUser, DirectoryJitPolicy::fromArray([]), $org->id, $mapped);

        $this->assertSame('conflict', $outcome->status);
        $this->assertSame('email_taken_non_directory', $outcome->reason);
        $this->assertNull($outcome->userId);

        // No takeover: the local account got NO grants, and no second user was created.
        $this->assertSame([], $this->activeRoleKeys($org->id, $local->id));
        $this->assertSame(1, User::query()->where('email', 'carol@acme.com')->count());
        $this->assertSame(1, User::query()->count());
    }

    // ── 5. protected_roles are filtered out of group-mapped grants ───────────────────────

    public function test_protected_roles_are_never_granted_via_group_mapping(): void
    {
        $org = $this->org();
        // "superadmin" is protected: a (possibly compromised) group_map row must not escalate to it.
        $policy = DirectoryJitPolicy::fromArray(['protected_roles' => ['app.superadmin']]);
        $mapper = new GroupMapper([
            'wheel' => 'app.superadmin',  // mapped to a PROTECTED role
            'staff' => 'app.staff',       // mapped to a normal role
        ]);
        $user = new DirectoryUser('dave', 'dave@acme.com', true, 'Dave', ['wheel', 'staff']);

        $mapped = $mapper->rolesFor($user->groups);
        $this->assertSame(['app.staff', 'app.superadmin'], $mapped); // mapper itself does not filter

        $outcome = (new DirectoryProvisioner)->provision($user, $policy, $org->id, $mapped);

        $this->assertSame('provisioned', $outcome->status);
        // Protected role filtered out; the other mapped role survives.
        $this->assertSame(['app.staff'], $this->activeRoleKeys($org->id, $outcome->userId, 'directory'));
        $this->assertNotContains('app.superadmin', $outcome->roles);
    }

    // ── 6. stale-grant revocation on re-sync; manual grants untouched ────────────────────

    public function test_resync_revokes_stale_directory_grant_but_keeps_manual_grant(): void
    {
        $org = $this->org();
        $mapper = new GroupMapper(['alpha' => 'app.a', 'beta' => 'app.b']);
        $provisioner = new DirectoryProvisioner;

        // First sync: groups [alpha, beta] → roles app.a, app.b.
        $userBoth = new DirectoryUser('erin', 'erin@acme.com', true, 'Erin', ['alpha', 'beta']);
        $first = $provisioner->provision($userBoth, DirectoryJitPolicy::fromArray([]), $org->id, $mapper->rolesFor($userBoth->groups));
        $this->assertSame('provisioned', $first->status);
        $uid = $first->userId;
        $this->assertSame(['app.a', 'app.b'], $this->activeRoleKeys($org->id, $uid, 'directory'));

        // A manually-assigned (non-directory) grant that must survive the sync.
        Grant::query()->create([
            'organization_id' => $org->id, 'subject_type' => 'user', 'subject_id' => $uid,
            'privilege_type' => 'role', 'privilege_key' => 'app.manual', 'source' => 'manual', 'valid_from' => now(),
        ]);

        // Re-sync: groups now [alpha] only → app.b must be revoked, app.a kept.
        $userAlpha = new DirectoryUser('erin', 'erin@acme.com', true, 'Erin', ['alpha']);
        $second = $provisioner->provision($userAlpha, DirectoryJitPolicy::fromArray([]), $org->id, $mapper->rolesFor($userAlpha->groups));
        $this->assertSame('linked', $second->status); // existing directory account → re-synced, not duplicated

        // app.a remains, app.b's directory grant is revoked.
        $this->assertSame(['app.a'], $this->activeRoleKeys($org->id, $uid, 'directory'));
        $revokedB = Grant::query()->where('subject_id', $uid)->where('privilege_key', 'app.b')->first();
        $this->assertNotNull($revokedB->revoked_at);
        $this->assertSame('directory_sync_removed', $revokedB->revoked_by);

        // Manual grant untouched.
        $manual = Grant::query()->where('subject_id', $uid)->where('privilege_key', 'app.manual')->first();
        $this->assertNull($manual->revoked_at);
        $this->assertSame('manual', $manual->source);
    }

    // ── 7. policy gates → pending outcomes ───────────────────────────────────────────────

    public function test_require_verified_email_gate_yields_pending(): void
    {
        $org = $this->org();
        $policy = DirectoryJitPolicy::fromArray(['require_verified_email' => true]);
        $user = new DirectoryUser('frank', 'frank@acme.com', false, 'Frank', []); // NOT verified

        $outcome = (new DirectoryProvisioner)->provision($user, $policy, $org->id, []);

        $this->assertSame('pending', $outcome->status);
        $this->assertSame('jit_requires_verified_email', $outcome->reason);
        $this->assertSame(0, User::query()->count()); // fail-closed: no row created
    }

    public function test_allowed_domains_gate_yields_pending(): void
    {
        $org = $this->org();
        $policy = DirectoryJitPolicy::fromArray(['allowed_domains' => ['acme.com']]);
        $user = new DirectoryUser('grace', 'grace@evil.com', true, 'Grace', []); // wrong domain

        $outcome = (new DirectoryProvisioner)->provision($user, $policy, $org->id, []);

        $this->assertSame('pending', $outcome->status);
        $this->assertSame('jit_domain_not_allowed', $outcome->reason);
        $this->assertSame(0, User::query()->count());
    }

    // ── 8. fail-closed authenticator: null credentials → denied, no IAM rows touched ─────

    public function test_authenticator_fails_closed_on_invalid_credentials(): void
    {
        $org = $this->org();
        $connector = new FakeDirectoryConnector(null); // authenticate() returns null
        $authenticator = new DirectoryAuthenticator(
            $connector,
            new GroupMapper(['alpha' => 'app.a']),
            new DirectoryProvisioner,
            ['jit' => [], 'organization_id' => $org->id],
        );

        $outcome = $authenticator->login('mallory', 'wrong-password');

        $this->assertSame('denied', $outcome->status);
        $this->assertSame('invalid_credentials', $outcome->reason);
        $this->assertFalse($outcome->ok());

        // No IAM rows touched.
        $this->assertSame(0, User::query()->count());
        $this->assertSame(0, Membership::query()->count());
        $this->assertSame(0, Grant::query()->count());
    }

    // ── bonus: end-to-end authenticator happy path through the fake connector ────────────

    public function test_authenticator_provisions_through_fake_connector(): void
    {
        $org = $this->org();
        $dirUser = new DirectoryUser('heidi', 'heidi@acme.com', true, 'Heidi', ['alpha']);
        $authenticator = new DirectoryAuthenticator(
            new FakeDirectoryConnector($dirUser),
            new GroupMapper(['alpha' => 'app.a']),
            new DirectoryProvisioner,
            ['jit' => ['default_roles' => ['app.member']], 'organization_id' => $org->id],
        );

        $outcome = $authenticator->login('heidi', 'right-password');

        $this->assertSame('provisioned', $outcome->status);
        $this->assertSame(['app.a', 'app.member'], $this->activeRoleKeys($org->id, $outcome->userId, 'directory'));
    }
}

/**
 * In-memory fake implementing the public DirectoryConnector contract — no ext-ldap required.
 * authenticate() returns the configured user (or null to simulate invalid credentials).
 */
final class FakeDirectoryConnector implements DirectoryConnector
{
    public function __construct(private readonly ?DirectoryUser $user) {}

    public function authenticate(string $username, string $password): ?DirectoryUser
    {
        return $this->user;
    }

    public function find(string $username): ?DirectoryUser
    {
        return $this->user;
    }
}
