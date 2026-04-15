package mfa

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/assertions"
	"github.com/travisbale/heimdall/test/_util/request"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestMFAEnrollment(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "mfa-enroll")
	ctx := context.Background()

	t.Run("complete enrollment flow", func(t *testing.T) {
		setupResp, err := user.Client.SetupMFA(ctx)
		require.NoError(t, err)

		assert.NotEmpty(t, setupResp.Secret)
		assert.NotEmpty(t, setupResp.QRCode)
		assert.Len(t, setupResp.BackupCodes, 10)

		// Verify backup codes are unique 8-digit strings
		codeSet := make(map[string]bool)
		for _, code := range setupResp.BackupCodes {
			assert.Len(t, code, 8)
			assert.False(t, codeSet[code], "backup codes should be unique")
			codeSet[code] = true
		}

		// MFA should not be enabled yet (two-step: setup then enable)
		status, err := user.Client.GetMFAStatus(ctx)
		require.NoError(t, err)
		assert.Nil(t, status.VerifiedAt)

		code := GenerateTOTPCode(t, setupResp.Secret)
		err = user.Client.EnableMFA(ctx, sdk.EnableMFARequest{Code: code})
		require.NoError(t, err)

		status, err = user.Client.GetMFAStatus(ctx)
		require.NoError(t, err)
		assert.NotNil(t, status.VerifiedAt)
		assert.Equal(t, 10, status.BackupCodesRemaining)
	})

	t.Run("setup fails when MFA already enabled", func(t *testing.T) {
		user := setup.CreateVerifiedUser(t, "mfa-already-enabled")
		EnableMFA(t, user.Client)

		_, err := user.Client.SetupMFA(ctx)
		assertions.AssertAPIError(t, err, http.StatusConflict, "setup should fail when MFA already enabled")
	})

	t.Run("enable fails with invalid code", func(t *testing.T) {
		user := setup.CreateVerifiedUser(t, "mfa-invalid-code")

		setupResp, err := user.Client.SetupMFA(ctx)
		require.NoError(t, err)

		err = user.Client.EnableMFA(ctx, sdk.EnableMFARequest{Code: "000000"})
		assertions.AssertAPIError(t, err, http.StatusBadRequest, "enabling with invalid code should fail")

		// Should still be able to enable with valid code
		code := GenerateTOTPCode(t, setupResp.Secret)
		err = user.Client.EnableMFA(ctx, sdk.EnableMFARequest{Code: code})
		require.NoError(t, err)
	})

	t.Run("enable fails without setup", func(t *testing.T) {
		user := setup.CreateVerifiedUser(t, "mfa-no-setup")

		err := user.Client.EnableMFA(ctx, sdk.EnableMFARequest{Code: "123456"})
		assertions.AssertAPIError(t, err, http.StatusNotFound, "enabling without setup should fail")
	})
}

func TestMFAEnableValidation(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "val-mfa-enable")
	token := setup.GetAccessToken(t, admin)

	t.Run("missing code", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1MFAEnable, `{}`, token)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "code")
	})

	t.Run("wrong length code", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1MFAEnable,
			`{"code":"12345"}`, token)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "code")
	})
}
