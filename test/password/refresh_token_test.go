package password

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestRefreshToken(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "refresh")

	t.Run("refresh returns new access token", func(t *testing.T) {
		resp, err := user.Client.RefreshToken(context.Background())
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
	})
}
