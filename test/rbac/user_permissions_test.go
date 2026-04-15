package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestDirectPermissions(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "direct-perms")
	ctx := context.Background()

	target := setup.CreateUserInTenant(t, admin, "perm-target")
	targetID := target.UserID

	perm := setup.GetPermissionByName(t, admin.Client, "role:read")

	t.Run("assign direct permission to user", func(t *testing.T) {
		err := admin.Client.SetDirectPermissions(ctx, sdk.SetDirectPermissionsRequest{
			UserID: targetID,
			Permissions: []sdk.DirectPermission{
				{PermissionID: perm.ID, Effect: sdk.PermissionAllow},
			},
		})
		require.NoError(t, err)

		perms, err := admin.Client.GetDirectPermissions(ctx, sdk.GetDirectPermissionsRequest{UserID: targetID})
		require.NoError(t, err)
		assert.Len(t, perms.Permissions, 1)
		assert.Equal(t, perm.ID, perms.Permissions[0].Permission.ID)
		assert.Equal(t, sdk.PermissionAllow, perms.Permissions[0].Effect)
	})

	t.Run("deny permission overrides allow", func(t *testing.T) {
		err := admin.Client.SetDirectPermissions(ctx, sdk.SetDirectPermissionsRequest{
			UserID: targetID,
			Permissions: []sdk.DirectPermission{
				{PermissionID: perm.ID, Effect: sdk.PermissionDeny},
			},
		})
		require.NoError(t, err)

		perms, err := admin.Client.GetDirectPermissions(ctx, sdk.GetDirectPermissionsRequest{UserID: targetID})
		require.NoError(t, err)
		assert.Len(t, perms.Permissions, 1)
		assert.Equal(t, perm.ID, perms.Permissions[0].Permission.ID)
		assert.Equal(t, sdk.PermissionDeny, perms.Permissions[0].Effect)
	})
}
