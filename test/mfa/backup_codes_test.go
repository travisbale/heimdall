package mfa

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestMFABackupCodes(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "mfa-backup")
	ctx := context.Background()

	setupResp := EnableMFA(t, user.Client)
	WaitForNewTOTPWindow(t)

	t.Run("login with backup code", func(t *testing.T) {
		client := setup.CreateClient(t)
		loginResp, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)

		// Use first backup code
		verifyResp, err := client.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
			ChallengeToken: loginResp.MFAChallengeToken,
			Code:           setupResp.BackupCodes[0],
		})
		require.NoError(t, err)
		assert.NotEmpty(t, verifyResp.AccessToken)

		// Backup code count should decrease
		status, err := user.Client.GetMFAStatus(ctx)
		require.NoError(t, err)
		assert.Equal(t, 9, status.BackupCodesRemaining)
	})

	t.Run("regenerate backup codes", func(t *testing.T) {
		newCodes, err := user.Client.RegenerateBackupCodes(ctx, sdk.RegenerateBackupCodesRequest{
			Password: user.Password,
		})
		require.NoError(t, err)
		assert.Len(t, newCodes.BackupCodes, 10)

		status, err := user.Client.GetMFAStatus(ctx)
		require.NoError(t, err)
		assert.Equal(t, 10, status.BackupCodesRemaining)
	})
}
