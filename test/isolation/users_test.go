package isolation

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestTenantIsolation_Users(t *testing.T) {
	t.Parallel()
	tenantA := createVerifiedUser(t, "iso-users-a")
	tenantB := createVerifiedUser(t, "iso-users-b")
	ctx := context.Background()

	t.Run("tenant A user profile is isolated", func(t *testing.T) {
		meA, err := tenantA.Client.GetMe(ctx)
		require.NoError(t, err)

		meB, err := tenantB.Client.GetMe(ctx)
		require.NoError(t, err)

		// Each user sees only their own profile
		assert.Equal(t, tenantA.Email, meA.Email)
		assert.Equal(t, tenantB.Email, meB.Email)
		assert.NotEqual(t, meA.TenantID, meB.TenantID, "users should be in different tenants")
	})
}

// The request has no tenant field, so the only tenant a caller can enrol into is its own.
// This is the property that lets the endpoint be reachable over HTTP at all.
func TestTenantIsolation_CreateUser(t *testing.T) {
	t.Parallel()
	adminA := createAdminUser(t, "iso-create-a")
	adminB := createAdminUser(t, "iso-create-b")
	ctx := context.Background()

	require.NotEqual(t, adminA.TenantID, adminB.TenantID)

	role, err := adminA.Client.CreateRole(ctx, sdk.CreateRoleRequest{
		Name:        "Isolated Role",
		Description: "Held by a user in tenant A",
	})
	require.NoError(t, err)

	email, password := setup.GenerateTestCredentials(t, "iso-created")
	created, err := adminA.Client.CreateUser(ctx, sdk.CreateUserRequest{
		Email:   email,
		RoleIDs: []uuid.UUID{role.ID},
	})
	require.NoError(t, err)
	assert.Equal(t, adminA.TenantID, created.TenantID)
	assert.NotEqual(t, adminB.TenantID, created.TenantID)

	t.Run("the account itself belongs to tenant A", func(t *testing.T) {
		client := setup.CreateClient(t)
		_, err := client.VerifyEmail(ctx, sdk.VerifyEmailRequest{
			Token:    created.VerificationToken,
			Password: password,
		})
		require.NoError(t, err)

		me, err := client.GetMe(ctx)
		require.NoError(t, err)
		assert.Equal(t, adminA.TenantID, me.TenantID)
	})

	// Asserted against what A sees for the same id. Reading B's answer alone proves nothing:
	// an empty list is what a user with no roles returns too.
	t.Run("tenant B reads nothing for the same user", func(t *testing.T) {
		seenByA, err := adminA.Client.GetUserRoles(ctx, sdk.GetUserRolesRequest{UserID: created.UserID})
		require.NoError(t, err)
		require.Len(t, seenByA.Roles, 1)

		seenByB, err := adminB.Client.GetUserRoles(ctx, sdk.GetUserRolesRequest{UserID: created.UserID})
		require.NoError(t, err)
		assert.Empty(t, seenByB.Roles, "another tenant's user has no roles to show")
	})
}
