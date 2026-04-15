package password

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestLogout(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "logout")

	t.Run("logout invalidates refresh token", func(t *testing.T) {
		_, err := user.Client.Logout(context.Background())
		require.NoError(t, err)

		// Refresh should fail after logout
		_, err = user.Client.RefreshToken(context.Background())
		assert.Error(t, err, "refresh should fail after logout")
	})
}
