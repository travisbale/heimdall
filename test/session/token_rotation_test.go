package session

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestTokenRotation(t *testing.T) {
	t.Parallel()
	user, jar := setup.CreateVerifiedUserWithJar(t, "token-rotation")
	ctx := context.Background()

	t.Run("refresh rotates token", func(t *testing.T) {
		oldCookie := setup.FindRefreshCookie(t, jar)

		resp, err := user.Client.RefreshToken(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)

		// Old cookie should be different from the new one
		newCookie := setup.FindRefreshCookie(t, jar)
		assert.NotEqual(t, oldCookie.Value, newCookie.Value, "refresh token should rotate")
	})

	t.Run("old token is rejected after rotation", func(t *testing.T) {
		oldCookie := setup.FindRefreshCookie(t, jar)

		// Refresh to rotate
		_, err := user.Client.RefreshToken(ctx)
		require.NoError(t, err)

		// Try using the old token
		replayClient := setup.CreateClientWithCookie(t, oldCookie)
		_, err = replayClient.RefreshToken(ctx)
		assert.Error(t, err, "old refresh token should be rejected")
	})
}
