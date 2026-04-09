//go:build integration

package test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

func TestTenantIsolation_Roles(t *testing.T) {
	// Two admin users in separate tenants
	tenantA := CreateAdminUser(t, "iso-roles-a")
	tenantB := CreateAdminUser(t, "iso-roles-b")
	ctx := context.Background()

	// Create a role in tenant A
	roleA, err := tenantA.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name:        "Tenant A Role",
		Description: "Belongs to tenant A",
	})
	require.NoError(t, err)

	t.Run("tenant B cannot see tenant A roles", func(t *testing.T) {
		roles, err := tenantB.Client.ListRoles(ctx)
		require.NoError(t, err)

		for _, r := range roles.Roles {
			assert.NotEqual(t, roleA.ID, r.ID, "tenant B should not see tenant A roles")
		}
	})

	t.Run("tenant B cannot get tenant A role by ID", func(t *testing.T) {
		_, err := tenantB.Client.GetRole(ctx, sdk.GetRoleRequest{RoleID: roleA.ID})
		assert.Error(t, err, "tenant B should not access tenant A role")
	})

	t.Run("tenant B delete of tenant A role is a no-op", func(t *testing.T) {
		// RLS filters the DELETE to 0 rows — no error, but nothing is deleted
		err := tenantB.Client.DeleteRole(ctx, sdk.DeleteRoleRequest{RoleID: roleA.ID})
		require.NoError(t, err)

		// Verify tenant A role still exists
		role, err := tenantA.Client.GetRole(ctx, sdk.GetRoleRequest{RoleID: roleA.ID})
		require.NoError(t, err)
		assert.Equal(t, roleA.ID, role.ID, "tenant A role should still exist")
	})
}

func TestTenantIsolation_UserRoles(t *testing.T) {
	tenantA := CreateAdminUser(t, "iso-userroles-a")
	tenantB := CreateAdminUser(t, "iso-userroles-b")
	ctx := context.Background()

	// Create a user in tenant A
	userA := CreateUserInTenant(t, tenantA, "iso-target-a")
	userAID := GetUserID(t, userA.Email)

	// Create a role in tenant A
	roleA, err := tenantA.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name:        "Tenant A Assignment Role",
		Description: "For cross-tenant assignment test",
	})
	require.NoError(t, err)

	// Assign role in tenant A
	err = tenantA.Client.SetUserRoles(ctx, sdk.SetUserRolesRequest{
		UserID:  userAID,
		RoleIDs: []uuid.UUID{roleA.ID},
	})
	require.NoError(t, err)

	t.Run("tenant B sees empty roles for tenant A user", func(t *testing.T) {
		// RLS filters the user — returns empty result, not an error
		roles, err := tenantB.Client.GetUserRoles(ctx, sdk.GetUserRolesRequest{UserID: userAID})
		require.NoError(t, err)
		assert.Empty(t, roles.Roles, "tenant B should see no roles for tenant A user")
	})

	t.Run("tenant B role assignment to tenant A user is a no-op", func(t *testing.T) {
		// RLS prevents cross-tenant modification — silent no-op
		err := tenantB.Client.SetUserRoles(ctx, sdk.SetUserRolesRequest{
			UserID:  userAID,
			RoleIDs: []uuid.UUID{},
		})
		require.NoError(t, err)

		// Verify tenant A user still has their role
		roles, err := tenantA.Client.GetUserRoles(ctx, sdk.GetUserRolesRequest{UserID: userAID})
		require.NoError(t, err)
		assert.Len(t, roles.Roles, 1, "tenant A user should still have their role")
	})
}

func TestTenantIsolation_Permissions(t *testing.T) {
	tenantA := CreateAdminUser(t, "iso-perms-a")
	tenantB := CreateAdminUser(t, "iso-perms-b")
	ctx := context.Background()

	t.Run("permissions are global across tenants", func(t *testing.T) {
		permsA, err := tenantA.Client.ListPermissions(ctx)
		require.NoError(t, err)

		permsB, err := tenantB.Client.ListPermissions(ctx)
		require.NoError(t, err)

		// Both tenants should see the same system permissions
		assert.Equal(t, len(permsA.Permissions), len(permsB.Permissions),
			"both tenants should see the same number of permissions")
	})
}

func TestTenantIsolation_Sessions(t *testing.T) {
	tenantA := CreateVerifiedUser(t, "iso-sessions-a")
	tenantB := CreateVerifiedUser(t, "iso-sessions-b")
	ctx := context.Background()

	t.Run("tenant B cannot see tenant A sessions", func(t *testing.T) {
		sessionsA, err := tenantA.Client.ListSessions(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, sessionsA.Sessions)

		sessionsB, err := tenantB.Client.ListSessions(ctx)
		require.NoError(t, err)

		// Tenant B's sessions should not contain tenant A's session IDs
		aIDs := make(map[uuid.UUID]bool)
		for _, s := range sessionsA.Sessions {
			aIDs[s.ID] = true
		}
		for _, s := range sessionsB.Sessions {
			assert.False(t, aIDs[s.ID], "tenant B should not see tenant A sessions")
		}
	})

	t.Run("tenant B cannot revoke tenant A session", func(t *testing.T) {
		sessionsA, err := tenantA.Client.ListSessions(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, sessionsA.Sessions)

		err = tenantB.Client.RevokeSession(ctx, sdk.RevokeSessionRequest{
			SessionID: sessionsA.Sessions[0].ID,
		})
		assert.Error(t, err, "tenant B should not revoke tenant A session")
	})
}
