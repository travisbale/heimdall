package isolation

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

func TestTenantIsolation_UserRoles(t *testing.T) {
	t.Parallel()
	tenantA := createAdminUser(t, "iso-userroles-a")
	tenantB := createAdminUser(t, "iso-userroles-b")
	ctx := context.Background()

	// Create a user in tenant A
	userA := createUserInTenant(t, tenantA, "iso-target-a")

	// Create a role in tenant A
	roleA, err := tenantA.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name:        "Tenant A Assignment Role",
		Description: "For cross-tenant assignment test",
	})
	require.NoError(t, err)

	// Assign role in tenant A
	err = tenantA.Client.SetUserRoles(ctx, sdk.SetUserRolesRequest{
		UserID:  userA.UserID,
		RoleIDs: []uuid.UUID{roleA.ID},
	})
	require.NoError(t, err)

	t.Run("tenant B sees empty roles for tenant A user", func(t *testing.T) {
		// RLS filters the user — returns empty result, not an error
		roles, err := tenantB.Client.GetUserRoles(ctx, sdk.GetUserRolesRequest{UserID: userA.UserID})
		require.NoError(t, err)
		assert.Empty(t, roles.Roles, "tenant B should see no roles for tenant A user")
	})

	t.Run("tenant B role assignment to tenant A user is a no-op", func(t *testing.T) {
		// RLS prevents cross-tenant modification — silent no-op
		err := tenantB.Client.SetUserRoles(ctx, sdk.SetUserRolesRequest{
			UserID:  userA.UserID,
			RoleIDs: []uuid.UUID{},
		})
		require.NoError(t, err)

		// Verify tenant A user still has their role
		roles, err := tenantA.Client.GetUserRoles(ctx, sdk.GetUserRolesRequest{UserID: userA.UserID})
		require.NoError(t, err)
		assert.Len(t, roles.Roles, 1, "tenant A user should still have their role")
	})
}
