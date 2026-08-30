package mfa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/database"
	"github.com/travisbale/heimdall/test/_util/setup"
)

// A password and a code are two halves of one sign-in, and the account can be deactivated
// between them. The challenge token says who passed the first half, not that they are still
// allowed the second — so the second half has to ask again rather than trust it.
func TestMFARefusesADeactivatedAccount(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "mfa-deactivated")
	ctx := context.Background()

	setupResp := EnableMFA(t, user.Client)
	WaitForNewTOTPWindow(t)

	client := setup.CreateClient(t)
	loginResp, err := client.Login(ctx, sdk.LoginRequest{Email: user.Email, Password: user.Password})
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.MFAChallengeToken, "the password half must have been accepted")

	database.SetUserStatus(t, user.Email, "suspended")

	_, err = client.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
		ChallengeToken: loginResp.MFAChallengeToken,
		Code:           GenerateTOTPCode(t, setupResp.Secret),
	})
	assert.Error(t, err, "a challenge issued before deactivation must not still complete a sign-in")
}
