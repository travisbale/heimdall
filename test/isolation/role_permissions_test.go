package isolation

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

func TestTenantIsolation_RolePermissions(t *testing.T) {
	t.Parallel()
	tenantA := createAdminUser(t, "iso-roleperms-a")
	tenantB := createAdminUser(t, "iso-roleperms-b")
	ctx := context.Background()

	// Create a role with permissions in tenant A
	roleA, err := tenantA.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name: "Role With Perms", Description: "Has permissions",
	})
	require.NoError(t, err)

	perm := getPermissionByName(t, tenantA.Client, "role:read")
	err = tenantA.Client.SetRolePermissions(ctx, sdk.SetRolePermissionsRequest{
		RoleID: roleA.ID, PermissionIDs: []uuid.UUID{perm.ID},
	})
	require.NoError(t, err)

	t.Run("tenant B cannot get tenant A role permissions", func(t *testing.T) {
		perms, err := tenantB.Client.GetRolePermissions(ctx, sdk.GetRolePermissionsRequest{
			RoleID: roleA.ID,
		})
		// RLS returns empty — role not visible to tenant B
		require.NoError(t, err)
		assert.Empty(t, perms.Permissions)
	})

	t.Run("tenant B cannot set tenant A role permissions", func(t *testing.T) {
		err := tenantB.Client.SetRolePermissions(ctx, sdk.SetRolePermissionsRequest{
			RoleID:        roleA.ID,
			PermissionIDs: []uuid.UUID{},
		})
		// Silent no-op via RLS
		require.NoError(t, err)

		// Tenant A permissions unchanged
		perms, err := tenantA.Client.GetRolePermissions(ctx, sdk.GetRolePermissionsRequest{
			RoleID: roleA.ID,
		})
		require.NoError(t, err)
		assert.Len(t, perms.Permissions, 1)
	})
}
