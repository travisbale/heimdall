//go:build integration

package test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

func TestListSessions(t *testing.T) {
	t.Parallel()
	user := CreateVerifiedUser(t, "sessions-list")
	ctx := context.Background()

	t.Run("user can list their sessions", func(t *testing.T) {
		sessions, err := user.Client.ListSessions(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, sessions.Sessions, "should have at least one session")

		s := sessions.Sessions[0]
		assert.NotEmpty(t, s.ID)
		assert.NotEmpty(t, s.UserAgent)
	})

	t.Run("multiple logins create multiple sessions", func(t *testing.T) {
		// Create additional sessions
		for i := 0; i < 2; i++ {
			client := harness.NewClient(t)
			_, err := client.Login(ctx, sdk.LoginRequest{
				Email:    user.Email,
				Password: user.Password,
			})
			require.NoError(t, err)
		}

		sessions, err := user.Client.ListSessions(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(sessions.Sessions), 3, "should have at least 3 sessions")
	})
}

func TestRevokeSession(t *testing.T) {
	t.Parallel()
	user := CreateVerifiedUser(t, "sessions-revoke")
	ctx := context.Background()

	// Create a second session
	otherClient := harness.NewClient(t)
	_, err := otherClient.Login(ctx, sdk.LoginRequest{
		Email:    user.Email,
		Password: user.Password,
	})
	require.NoError(t, err)

	t.Run("revoke specific session", func(t *testing.T) {
		sessions, err := user.Client.ListSessions(ctx)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(sessions.Sessions), 2)

		// Revoke the first session in the list
		err = user.Client.RevokeSession(ctx, sdk.RevokeSessionRequest{
			SessionID: sessions.Sessions[0].ID,
		})
		require.NoError(t, err)

		// Session count should decrease
		after, err := user.Client.ListSessions(ctx)
		require.NoError(t, err)
		assert.Less(t, len(after.Sessions), len(sessions.Sessions))
	})
}

func TestRevokeAllSessions(t *testing.T) {
	t.Parallel()
	user := CreateVerifiedUser(t, "sessions-revoke-all")
	ctx := context.Background()

	// Create extra sessions
	for i := 0; i < 2; i++ {
		client := harness.NewClient(t)
		_, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)
	}

	t.Run("revoke all sessions", func(t *testing.T) {
		err := user.Client.RevokeAllSessions(ctx)
		require.NoError(t, err)

		// Refresh should fail since all sessions are revoked
		_, err = user.Client.RefreshToken(ctx)
		assert.Error(t, err, "refresh should fail after revoking all sessions")
	})

	t.Run("can login again after revoking all", func(t *testing.T) {
		resp, err := user.Client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
	})
}

func TestTokenRotation(t *testing.T) {
	t.Parallel()
	user, jar := CreateVerifiedUserWithJar(t, "token-rotation")
	ctx := context.Background()

	t.Run("refresh rotates token", func(t *testing.T) {
		oldCookie := FindRefreshCookie(t, jar)

		resp, err := user.Client.RefreshToken(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)

		// Old cookie should be different from the new one
		newCookie := FindRefreshCookie(t, jar)
		assert.NotEqual(t, oldCookie.Value, newCookie.Value, "refresh token should rotate")
	})

	t.Run("old token is rejected after rotation", func(t *testing.T) {
		oldCookie := FindRefreshCookie(t, jar)

		// Refresh to rotate
		_, err := user.Client.RefreshToken(ctx)
		require.NoError(t, err)

		// Try using the old token
		replayClient := NewClientWithCookie(t, oldCookie)
		_, err = replayClient.RefreshToken(ctx)
		assert.Error(t, err, "old refresh token should be rejected")
	})
}
