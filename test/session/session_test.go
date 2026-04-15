package session

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestListSessions(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "sessions-list")
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
			client := setup.CreateClient(t)
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
	user := setup.CreateVerifiedUser(t, "sessions-revoke")
	ctx := context.Background()

	// Create a second session
	otherClient := setup.CreateClient(t)
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
	user := setup.CreateVerifiedUser(t, "sessions-revoke-all")
	ctx := context.Background()

	// Create extra sessions
	for i := 0; i < 2; i++ {
		client := setup.CreateClient(t)
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
