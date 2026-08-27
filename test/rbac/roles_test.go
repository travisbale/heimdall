package rbac

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/assertions"
	"github.com/travisbale/heimdall/test/_util/request"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestListPermissions(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "perms-list")
	ctx := context.Background()

	perms, err := admin.Client.ListPermissions(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, perms.Permissions, "should have seeded permissions")

	// A constant with no seeded row cannot be granted; a row with no constant is unenforceable.
	seeded := make([]iam.Scope, 0, len(perms.Permissions))
	for _, p := range perms.Permissions {
		seeded = append(seeded, iam.Scope(p.Name))
	}
	assert.ElementsMatch(t, iam.AllScopes, seeded,
		"seeded permissions must match iam.AllScopes exactly")
}

func TestRoleCRUD(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "role-crud")
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
			assertions.AssertAPIError(t, err, http.StatusNotFound, "deleted role should not be found")
		})
	})
}

func TestRolePermissions(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "role-perms")
	ctx := context.Background()

	role, err := admin.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name:        "Permission Test Role",
		Description: "For testing permission assignment",
	})
	require.NoError(t, err)

	perm := setup.GetPermissionByName(t, admin.Client, iam.ScopeRoleRead)

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

func TestCreateRoleValidation(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "val-create-role")
	token := setup.GetAccessToken(t, admin)

	t.Run("missing name", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1Roles,
			`{"description":"test"}`, token)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "name")
	})

	t.Run("missing description", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1Roles,
			`{"name":"test"}`, token)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "description")
	})
}

// Both of these answered 500 with "Sorry, something went wrong", which reads as a server
// fault to a caller who chose the name — and hid the conflict from anything retrying.
func TestRoleWriteConflicts(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "role-conflicts")
	ctx := context.Background()

	first, err := admin.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name:        "Duplicated",
		Description: "The first one",
	})
	require.NoError(t, err)

	t.Run("creating a second role with the same name conflicts", func(t *testing.T) {
		_, err := admin.Client.CreateRole(ctx, sdk.CreateRoleRequest{
			Name:        "Duplicated",
			Description: "The second one",
		})
		assertions.AssertAPIError(t, err, http.StatusConflict, "a taken name is the caller's to fix")
	})

	t.Run("renaming a role onto a taken name conflicts", func(t *testing.T) {
		other, err := admin.Client.CreateRole(ctx, sdk.CreateRoleRequest{
			Name:        "Renameable",
			Description: "Will be renamed onto the first",
		})
		require.NoError(t, err)

		taken := first.Name
		_, err = admin.Client.UpdateRole(ctx, sdk.UpdateRoleRequest{RoleID: other.ID, Name: &taken})
		assertions.AssertAPIError(t, err, http.StatusConflict, "the rename collides with an existing role")
	})

	t.Run("updating a role that is not there is not found", func(t *testing.T) {
		name := "Nowhere"
		_, err := admin.Client.UpdateRole(ctx, sdk.UpdateRoleRequest{RoleID: uuid.New(), Name: &name})
		assertions.AssertAPIError(t, err, http.StatusNotFound, "no row to update is a 404, not a fault")
	})

	// Tenants are separate namespaces for role names — the constraint is on the pair, and a
	// conflict raised across tenants would be a leak as much as a bug.
	t.Run("another tenant may still use the name", func(t *testing.T) {
		other := setup.CreateAdminUser(t, "role-conflicts-other")
		_, err := other.Client.CreateRole(ctx, sdk.CreateRoleRequest{
			Name:        "Duplicated",
			Description: "Same name, different tenant",
		})
		require.NoError(t, err)
	})
}
