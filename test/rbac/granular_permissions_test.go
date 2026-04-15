package rbac

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/assertions"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestGranularPermissions(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "granular")
	ctx := context.Background()

	// Create an unprivileged user in the same tenant
	user := setup.CreateUserInTenant(t, admin, "granular-user")

	t.Run("role:read allows list and get but not create", func(t *testing.T) {
		roleReadPerm := setup.GetPermissionByName(t, admin.Client, "role:read")

		err := admin.Client.SetDirectPermissions(ctx, sdk.SetDirectPermissionsRequest{
			UserID: user.UserID,
			Permissions: []sdk.DirectPermission{
				{PermissionID: roleReadPerm.ID, Effect: sdk.PermissionAllow},
			},
		})
		require.NoError(t, err)

		// Re-login to get updated JWT
		_, err = user.Client.Login(ctx, sdk.LoginRequest{
			Email: user.Email, Password: user.Password,
		})
		require.NoError(t, err)

		// Should be able to list and get roles
		_, err = user.Client.ListRoles(ctx)
		require.NoError(t, err)

		_, err = user.Client.ListPermissions(ctx)
		require.NoError(t, err)

		// Should not be able to create roles
		_, err = user.Client.CreateRole(ctx, sdk.CreateRoleRequest{
			Name: "Unauthorized", Description: "Should fail",
		})
		assertions.AssertAPIError(t, err, http.StatusForbidden, "role:read should not allow create")
	})

	t.Run("deny overrides allow from role", func(t *testing.T) {
		roleReadPerm := setup.GetPermissionByName(t, admin.Client, "role:read")
		roleCreatePerm := setup.GetPermissionByName(t, admin.Client, "role:create")

		// Grant role:create (allow) and role:read (deny)
		err := admin.Client.SetDirectPermissions(ctx, sdk.SetDirectPermissionsRequest{
			UserID: user.UserID,
			Permissions: []sdk.DirectPermission{
				{PermissionID: roleCreatePerm.ID, Effect: sdk.PermissionAllow},
				{PermissionID: roleReadPerm.ID, Effect: sdk.PermissionDeny},
			},
		})
		require.NoError(t, err)

		_, err = user.Client.Login(ctx, sdk.LoginRequest{
			Email: user.Email, Password: user.Password,
		})
		require.NoError(t, err)

		// role:read is denied, so list should fail
		_, err = user.Client.ListRoles(ctx)
		assertions.AssertAPIError(t, err, http.StatusForbidden, "deny should override allow")
	})
}
