package rbac

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestUserRoles(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "user-roles")
	ctx := context.Background()

	// Create a target user in the same tenant
	target := setup.CreateUserInTenant(t, admin, "role-target")
	targetID := target.UserID

	role, err := admin.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name:        "Assignable Role",
		Description: "For user role assignment tests",
	})
	require.NoError(t, err)

	t.Run("assign role to user", func(t *testing.T) {
		err := admin.Client.SetUserRoles(ctx, sdk.SetUserRolesRequest{
			UserID:  targetID,
			RoleIDs: []uuid.UUID{role.ID},
		})
		require.NoError(t, err)

		roles, err := admin.Client.GetUserRoles(ctx, sdk.GetUserRolesRequest{UserID: targetID})
		require.NoError(t, err)
		assert.Len(t, roles.Roles, 1)
		assert.Equal(t, role.ID, roles.Roles[0].ID)
	})

	t.Run("clear roles from user", func(t *testing.T) {
		err := admin.Client.SetUserRoles(ctx, sdk.SetUserRolesRequest{
			UserID:  targetID,
			RoleIDs: []uuid.UUID{},
		})
		require.NoError(t, err)

		roles, err := admin.Client.GetUserRoles(ctx, sdk.GetUserRolesRequest{UserID: targetID})
		require.NoError(t, err)
		assert.Empty(t, roles.Roles)
	})
}
