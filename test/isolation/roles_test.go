package isolation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

func TestTenantIsolation_Roles(t *testing.T) {
	t.Parallel()
	// Two admin users in separate tenants
	tenantA := createAdminUser(t, "iso-roles-a")
	tenantB := createAdminUser(t, "iso-roles-b")
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
