package isolation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
