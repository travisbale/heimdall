package isolation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantIsolation_Permissions(t *testing.T) {
	t.Parallel()
	tenantA := createAdminUser(t, "iso-perms-a")
	tenantB := createAdminUser(t, "iso-perms-b")
	ctx := context.Background()

	t.Run("permissions are global across tenants", func(t *testing.T) {
		permsA, err := tenantA.Client.ListPermissions(ctx)
		require.NoError(t, err)

		permsB, err := tenantB.Client.ListPermissions(ctx)
		require.NoError(t, err)

		// Both tenants should see the same system permissions
		assert.Equal(t, len(permsA.Permissions), len(permsB.Permissions),
			"both tenants should see the same number of permissions")
	})
}
