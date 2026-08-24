package rbac

import (
	"context"
	"net/http"
	"testing"

	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/assertions"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestUnauthorizedRBACAccess(t *testing.T) {
	t.Parallel()
	// BootstrapTenant gives the first user System Admin; one created through gRPC inside the
	// tenant gets no roles at all, which is the pair this needs.
	admin := setup.CreateAdminUser(t, "rbac-admin")
	ctx := context.Background()

	// Create a second user in the admin's tenant via gRPC (no roles assigned)
	unprivileged := setup.CreateUserInTenant(t, admin, "unprivileged")

	t.Run("cannot list permissions without role:read", func(t *testing.T) {
		_, err := unprivileged.Client.ListPermissions(ctx)
		assertions.AssertAPIError(t, err, http.StatusForbidden, "should be forbidden")
	})

	t.Run("cannot create role without role:create", func(t *testing.T) {
		_, err := unprivileged.Client.CreateRole(ctx, sdk.CreateRoleRequest{
			Name:        "Unauthorized Role",
			Description: "Should fail",
		})
		assertions.AssertAPIError(t, err, http.StatusForbidden, "should be forbidden")
	})

	t.Run("cannot list roles without role:read", func(t *testing.T) {
		_, err := unprivileged.Client.ListRoles(ctx)
		assertions.AssertAPIError(t, err, http.StatusForbidden, "should be forbidden")
	})
}
