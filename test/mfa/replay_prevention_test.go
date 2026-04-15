package mfa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestTOTPReplayPrevention(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "mfa-replay")
	ctx := context.Background()

	setupResp := EnableMFA(t, user.Client)
	WaitForNewTOTPWindow(t)

	t.Run("same code rejected twice within same window", func(t *testing.T) {
		client := setup.CreateClient(t)
		loginResp, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)

		code := GenerateTOTPCode(t, setupResp.Secret)

		// First use succeeds
		_, err = client.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
			ChallengeToken: loginResp.MFAChallengeToken,
			Code:           code,
		})
		require.NoError(t, err)

		// Second login to get a new challenge token
		client2 := setup.CreateClient(t)
		loginResp2, err := client2.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)

		// Same code should be rejected (replay prevention)
		_, err = client2.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
			ChallengeToken: loginResp2.MFAChallengeToken,
			Code:           code,
		})
		assert.Error(t, err, "same TOTP code should be rejected within same window")
	})
}
