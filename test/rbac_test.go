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

func TestListPermissions(t *testing.T) {
	admin := CreateAdminUser(t, "perms-list")
	ctx := context.Background()

	perms, err := admin.Client.ListPermissions(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, perms.Permissions, "should have seeded permissions")

	// Verify expected permission names exist
	names := make(map[string]bool)
	for _, p := range perms.Permissions {
		names[p.Name] = true
	}
	assert.True(t, names["role:create"], "should have role:create permission")
	assert.True(t, names["user:assign"], "should have user:assign permission")
}

func TestRoleCRUD(t *testing.T) {
	admin := CreateAdminUser(t, "role-crud")
	ctx := context.Background()

	t.Run("create role", func(t *testing.T) {
		role, err := admin.Client.CreateRole(ctx, sdk.CreateRoleRequest{
			Name:        "Test Role",
			Description: "A test role",
		})
		require.NoError(t, err)
		assert.Equal(t, "Test Role", role.Name)
		assert.Equal(t, "A test role", role.Description)

		t.Run("get role", func(t *testing.T) {
			got, err := admin.Client.GetRole(ctx, sdk.GetRoleRequest{RoleID: role.ID})
			require.NoError(t, err)
			assert.Equal(t, role.ID, got.ID)
			assert.Equal(t, "Test Role", got.Name)
		})

		t.Run("list roles includes created role", func(t *testing.T) {
			roles, err := admin.Client.ListRoles(ctx)
			require.NoError(t, err)

			found := false
			for _, r := range roles.Roles {
				if r.ID == role.ID {
					found = true
				}
			}
			assert.True(t, found, "created role should appear in list")
		})

		t.Run("update role", func(t *testing.T) {
			newName := "Updated Role"
			updated, err := admin.Client.UpdateRole(ctx, sdk.UpdateRoleRequest{
				RoleID: role.ID,
				Name:   &newName,
			})
			require.NoError(t, err)
			assert.Equal(t, "Updated Role", updated.Name)
		})

		t.Run("delete role", func(t *testing.T) {
			err := admin.Client.DeleteRole(ctx, sdk.DeleteRoleRequest{RoleID: role.ID})
			require.NoError(t, err)

			// Verify it's gone
			_, err = admin.Client.GetRole(ctx, sdk.GetRoleRequest{RoleID: role.ID})
			AssertStatus404(t, err, "deleted role should not be found")
		})
	})
}

func TestRolePermissions(t *testing.T) {
	admin := CreateAdminUser(t, "role-perms")
	ctx := context.Background()

	role, err := admin.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name:        "Permission Test Role",
		Description: "For testing permission assignment",
	})
	require.NoError(t, err)

	perm := GetPermissionByName(t, admin.Client, "role:read")

	t.Run("assign permissions to role", func(t *testing.T) {
		err := admin.Client.SetRolePermissions(ctx, sdk.SetRolePermissionsRequest{
			RoleID:        role.ID,
			PermissionIDs: []uuid.UUID{perm.ID},
		})
		require.NoError(t, err)

		perms, err := admin.Client.GetRolePermissions(ctx, sdk.GetRolePermissionsRequest{RoleID: role.ID})
		require.NoError(t, err)
		assert.Len(t, perms.Permissions, 1)
		assert.Equal(t, perm.ID, perms.Permissions[0].ID)
	})

	t.Run("clear permissions from role", func(t *testing.T) {
		err := admin.Client.SetRolePermissions(ctx, sdk.SetRolePermissionsRequest{
			RoleID:        role.ID,
			PermissionIDs: []uuid.UUID{},
		})
		require.NoError(t, err)

		perms, err := admin.Client.GetRolePermissions(ctx, sdk.GetRolePermissionsRequest{RoleID: role.ID})
		require.NoError(t, err)
		assert.Empty(t, perms.Permissions)
	})
}

func TestUserRoles(t *testing.T) {
	admin := CreateAdminUser(t, "user-roles")
	ctx := context.Background()

	// Create a target user in the same tenant
	target := CreateUserInTenant(t, admin, "role-target")
	targetID := GetUserID(t, target.Email)

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

func TestDirectPermissions(t *testing.T) {
	admin := CreateAdminUser(t, "direct-perms")
	ctx := context.Background()

	target := CreateUserInTenant(t, admin, "perm-target")
	targetID := GetUserID(t, target.Email)

	perm := GetPermissionByName(t, admin.Client, "role:read")

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

func TestUnauthorizedRBACAccess(t *testing.T) {
	// Create an admin user, then create a second user in the same tenant without roles.
	// BootstrapTenant gives the first user System Admin, but users created via gRPC
	// within the tenant get no roles by default.
	admin := CreateAdminUser(t, "rbac-admin")
	ctx := context.Background()

	// Create a second user in the admin's tenant via gRPC (no roles assigned)
	unprivileged := CreateUserInTenant(t, admin, "unprivileged")

	t.Run("cannot list permissions without role:read", func(t *testing.T) {
		_, err := unprivileged.Client.ListPermissions(ctx)
		AssertStatus403(t, err, "should be forbidden")
	})

	t.Run("cannot create role without role:create", func(t *testing.T) {
		_, err := unprivileged.Client.CreateRole(ctx, sdk.CreateRoleRequest{
			Name:        "Unauthorized Role",
			Description: "Should fail",
		})
		AssertStatus403(t, err, "should be forbidden")
	})

	t.Run("cannot list roles without role:read", func(t *testing.T) {
		_, err := unprivileged.Client.ListRoles(ctx)
		AssertStatus403(t, err, "should be forbidden")
	})
}
