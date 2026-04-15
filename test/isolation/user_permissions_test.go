package isolation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

func TestTenantIsolation_UserPermissions(t *testing.T) {
	t.Parallel()
	tenantA := createAdminUser(t, "iso-userperms-a")
	tenantB := createAdminUser(t, "iso-userperms-b")
	ctx := context.Background()

	userA := createUserInTenant(t, tenantA, "iso-permtarget-a")

	perm := getPermissionByName(t, tenantA.Client, "role:read")
	err := tenantA.Client.SetDirectPermissions(ctx, sdk.SetDirectPermissionsRequest{
		UserID: userA.UserID,
		Permissions: []sdk.DirectPermission{
			{PermissionID: perm.ID, Effect: sdk.PermissionAllow},
		},
	})
	require.NoError(t, err)

	t.Run("tenant B cannot get tenant A user permissions", func(t *testing.T) {
		perms, err := tenantB.Client.GetDirectPermissions(ctx, sdk.GetDirectPermissionsRequest{
			UserID: userA.UserID,
		})
		require.NoError(t, err)
		assert.Empty(t, perms.Permissions, "tenant B should see no permissions for tenant A user")
	})

	t.Run("tenant B cannot set tenant A user permissions", func(t *testing.T) {
		err := tenantB.Client.SetDirectPermissions(ctx, sdk.SetDirectPermissionsRequest{
			UserID:      userA.UserID,
			Permissions: []sdk.DirectPermission{},
		})
		require.NoError(t, err)

		// Tenant A permissions unchanged
		perms, err := tenantA.Client.GetDirectPermissions(ctx, sdk.GetDirectPermissionsRequest{
			UserID: userA.UserID,
		})
		require.NoError(t, err)
		assert.Len(t, perms.Permissions, 1)
	})
}
