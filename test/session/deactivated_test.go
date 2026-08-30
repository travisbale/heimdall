package session

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/test/_util/database"
	"github.com/travisbale/heimdall/test/_util/setup"
)

// Refusing a deactivated account at the login form is only half of it: the access it already
// holds has to end too. A refresh mints a new access token and a new refresh token, so a
// session that keeps refreshing never expires, and deactivating an account that is signed in
// does nothing at all until it does.
func TestRefreshEndsWhenTheAccountIsDeactivated(t *testing.T) {
	t.Parallel()
	user, jar := setup.CreateVerifiedUserWithJar(t, "deactivated-refresh")
	ctx := context.Background()

	// A refresh works while the account is active, so a failure below is the status and not
	// the cookie.
	_, err := user.Client.RefreshToken(ctx)
	require.NoError(t, err, "refresh should work before deactivation")
	require.NotNil(t, setup.FindRefreshCookie(t, jar))

	database.SetUserStatus(t, user.Email, "suspended")

	_, err = user.Client.RefreshToken(ctx)
	assert.Error(t, err, "a suspended account must not be able to refresh its session")
}
