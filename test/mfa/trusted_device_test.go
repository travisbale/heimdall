package mfa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestTrustedDevice(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "mfa-trusted")
	ctx := context.Background()

	setupResp := EnableMFA(t, user.Client)
	WaitForNewTOTPWindow(t)

	t.Run("trusted device skips MFA on subsequent login", func(t *testing.T) {
		client := setup.CreateClient(t)

		// Login and verify MFA with trust_device=true
		loginResp, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)
		require.NotEmpty(t, loginResp.MFAChallengeToken)

		code := GenerateTOTPCode(t, setupResp.Secret)
		verifyResp, err := client.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
			ChallengeToken: loginResp.MFAChallengeToken,
			Code:           code,
			TrustDevice:    true,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, verifyResp.AccessToken)

		WaitForNewTOTPWindow(t)

		// Subsequent login with same client should skip MFA (device is trusted)
		loginResp2, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, loginResp2.AccessToken, "should get access token directly on trusted device")
		assert.Empty(t, loginResp2.MFAChallengeToken, "should not get MFA challenge on trusted device")
	})
}
