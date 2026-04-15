package mfa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestRequiredMFASetup(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "mfa-required")
	ctx := context.Background()

	// Create a verified user with an MFA-required role (role creation handled inside helper)
	user := CreateUserWithMFARequiredRole(t, admin, "mfa-required-user")

	t.Run("login returns setup token when MFA required", func(t *testing.T) {
		loginResp, err := user.Client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, loginResp.MFASetupToken, "should receive MFA setup token")
		assert.Empty(t, loginResp.AccessToken, "should not receive access token")
		assert.Empty(t, loginResp.MFAChallengeToken, "should not receive challenge token")

		t.Run("complete required MFA setup", func(t *testing.T) {
			// Step 1: Setup MFA using setup token
			setupResp, err := user.Client.RequiredMFASetup(ctx, sdk.RequiredMFASetupRequest{
				SetupToken: loginResp.MFASetupToken,
			})
			require.NoError(t, err)
			assert.NotEmpty(t, setupResp.Secret)
			assert.NotEmpty(t, setupResp.BackupCodes)

			// Step 2: Enable MFA
			code := GenerateTOTPCode(t, setupResp.Secret)
			enableResp, err := user.Client.RequiredMFAEnable(ctx, sdk.RequiredMFAEnableRequest{
				SetupToken: loginResp.MFASetupToken,
				Code:       code,
			})
			require.NoError(t, err)
			assert.NotEmpty(t, enableResp.MFAChallengeToken)

			// Step 3: Verify MFA to complete login
			WaitForNewTOTPWindow(t)
			newCode := GenerateTOTPCode(t, setupResp.Secret)
			verifyResp, err := user.Client.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
				ChallengeToken: enableResp.MFAChallengeToken,
				Code:           newCode,
			})
			require.NoError(t, err)
			assert.NotEmpty(t, verifyResp.AccessToken)
		})
	})
}
