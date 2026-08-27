package password

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
	"github.com/travisbale/heimdall/test/_util/setup"
)

// Registration bootstraps a tenant; this enrols into one that exists. The two are the only
// ways a user is made, and confusing them puts an account where nothing can see it.
func TestCreateUser(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "create-user")
	ctx := context.Background()

	t.Run("creates the user in the caller's tenant", func(t *testing.T) {
		email, password := setup.GenerateTestCredentials(t, "created")

		created, err := admin.Client.CreateUser(ctx, sdk.CreateUserRequest{Email: email})
		require.NoError(t, err)
		assert.Equal(t, email, created.Email)
		assert.Equal(t, admin.TenantID, created.TenantID)

		// The response carries the only copy: nothing is emailed on this path, which is what
		// lets the caller decide how the person is told.
		require.NotEmpty(t, created.VerificationToken)

		client := setup.CreateClient(t)
		_, err = client.VerifyEmail(ctx, sdk.VerifyEmailRequest{
			Token:    created.VerificationToken,
			Password: password,
		})
		require.NoError(t, err)

		_, err = client.Login(ctx, sdk.LoginRequest{Email: email, Password: password})
		require.NoError(t, err, "the created account should be usable once verified")
	})

	t.Run("assigns the roles it was given", func(t *testing.T) {
		role, err := admin.Client.CreateRole(ctx, sdk.CreateRoleRequest{
			Name:        "Created With Role",
			Description: "Assigned at creation",
		})
		require.NoError(t, err)

		email, _ := setup.GenerateTestCredentials(t, "created-roles")
		created, err := admin.Client.CreateUser(ctx, sdk.CreateUserRequest{
			Email:   email,
			RoleIDs: []uuid.UUID{role.ID},
		})
		require.NoError(t, err)

		roles, err := admin.Client.GetUserRoles(ctx, sdk.GetUserRolesRequest{UserID: created.UserID})
		require.NoError(t, err)
		names := make([]string, 0, len(roles.Roles))
		for _, r := range roles.Roles {
			names = append(names, r.Name)
		}
		assert.Contains(t, names, "Created With Role")
	})

	// The unique index is partial — active rows only — so the database permits a second
	// pending account for one address, holding a token that could never be redeemed.
	t.Run("refuses an address already taken, still pending", func(t *testing.T) {
		email, _ := setup.GenerateTestCredentials(t, "created-dup")

		_, err := admin.Client.CreateUser(ctx, sdk.CreateUserRequest{Email: email})
		require.NoError(t, err)

		_, err = admin.Client.CreateUser(ctx, sdk.CreateUserRequest{Email: email})
		assertions.AssertAPIError(t, err, http.StatusConflict, "a second create should conflict, not fault")
	})

	t.Run("refuses an address already verified", func(t *testing.T) {
		email, password := setup.GenerateTestCredentials(t, "created-dup-active")

		created, err := admin.Client.CreateUser(ctx, sdk.CreateUserRequest{Email: email})
		require.NoError(t, err)
		_, err = setup.CreateClient(t).VerifyEmail(ctx, sdk.VerifyEmailRequest{
			Token:    created.VerificationToken,
			Password: password,
		})
		require.NoError(t, err)

		_, err = admin.Client.CreateUser(ctx, sdk.CreateUserRequest{Email: email})
		assertions.AssertAPIError(t, err, http.StatusConflict, "the address belongs to a live account")
	})

	// Not CreateVerifiedUser: registering bootstraps a tenant and makes the registrant its
	// administrator, so that fixture holds every scope there is.
	t.Run("refuses a caller without the scope", func(t *testing.T) {
		plain := setup.CreateUserInTenant(t, admin, "create-user-unscoped")
		email, _ := setup.GenerateTestCredentials(t, "created-refused")

		_, err := plain.Client.CreateUser(ctx, sdk.CreateUserRequest{Email: email})
		assertions.AssertAPIError(t, err, http.StatusForbidden, "user:create is required")
	})

	t.Run("refuses a caller with no session", func(t *testing.T) {
		email, _ := setup.GenerateTestCredentials(t, "created-anon")

		_, err := setup.CreateClient(t).CreateUser(ctx, sdk.CreateUserRequest{Email: email})
		assertions.AssertAPIError(t, err, http.StatusUnauthorized, "creating a user is never anonymous")
	})

	t.Run("the scope is one an admin actually holds", func(t *testing.T) {
		// The route would be unreachable if nothing granted it, and it gated no route at all
		// before this one existed.
		assert.Contains(t, iam.AllScopes, iam.ScopeUserCreate)
	})
}
