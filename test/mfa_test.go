//go:build integration

package test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

const totpPeriod = 3 // Must match TOTPPeriod in harness config

// generateTOTPCode generates a TOTP code using the 3-second test period
func generateTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period: totpPeriod,
		Digits: otp.DigitsSix,
	})
	require.NoError(t, err)
	return code
}

// waitForNewTOTPWindow waits until the next TOTP window to avoid replay detection
func waitForNewTOTPWindow(t *testing.T) {
	t.Helper()
	now := time.Now()
	msIntoWindow := now.UnixMilli() % (totpPeriod * 1000)
	waitTime := time.Duration(totpPeriod*1000-msIntoWindow+100) * time.Millisecond
	time.Sleep(waitTime)
}

// enableMFA completes setup + enable in a single call
func enableMFA(t *testing.T, client *sdk.HTTPClient) *sdk.MFASetupResponse {
	t.Helper()
	ctx := context.Background()

	setupResp, err := client.SetupMFA(ctx)
	require.NoError(t, err)

	code := generateTOTPCode(t, setupResp.Secret)
	err = client.EnableMFA(ctx, sdk.EnableMFARequest{Code: code})
	require.NoError(t, err)

	return setupResp
}

func TestMFAEnrollment(t *testing.T) {
	user := CreateVerifiedUser(t, "mfa-enroll")
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

		code := generateTOTPCode(t, setupResp.Secret)
		err = user.Client.EnableMFA(ctx, sdk.EnableMFARequest{Code: code})
		require.NoError(t, err)

		status, err = user.Client.GetMFAStatus(ctx)
		require.NoError(t, err)
		assert.NotNil(t, status.VerifiedAt)
		assert.Equal(t, 10, status.BackupCodesRemaining)
	})

	t.Run("setup fails when MFA already enabled", func(t *testing.T) {
		user := CreateVerifiedUser(t, "mfa-already-enabled")
		enableMFA(t, user.Client)

		_, err := user.Client.SetupMFA(ctx)
		AssertAPIError(t, err, http.StatusConflict, "setup should fail when MFA already enabled")
	})

	t.Run("enable fails with invalid code", func(t *testing.T) {
		user := CreateVerifiedUser(t, "mfa-invalid-code")

		setupResp, err := user.Client.SetupMFA(ctx)
		require.NoError(t, err)

		err = user.Client.EnableMFA(ctx, sdk.EnableMFARequest{Code: "000000"})
		AssertAPIError(t, err, http.StatusBadRequest, "enabling with invalid code should fail")

		// Should still be able to enable with valid code
		code := generateTOTPCode(t, setupResp.Secret)
		err = user.Client.EnableMFA(ctx, sdk.EnableMFARequest{Code: code})
		require.NoError(t, err)
	})

	t.Run("enable fails without setup", func(t *testing.T) {
		user := CreateVerifiedUser(t, "mfa-no-setup")

		err := user.Client.EnableMFA(ctx, sdk.EnableMFARequest{Code: "123456"})
		AssertAPIError(t, err, http.StatusNotFound, "enabling without setup should fail")
	})
}

func TestMFALogin(t *testing.T) {
	user := CreateVerifiedUser(t, "mfa-login")
	ctx := context.Background()

	setupResp := enableMFA(t, user.Client)
	waitForNewTOTPWindow(t)

	t.Run("complete MFA login flow", func(t *testing.T) {
		client := harness.NewClient(t)

		// Password auth returns MFA challenge token, not access token
		loginResp, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, loginResp.MFAChallengeToken)
		assert.Empty(t, loginResp.AccessToken, "should not receive access token before MFA")

		// Verify challenge token has correct audience and no scopes
		claims := ExtractMFAChallengeClaims(t, loginResp.MFAChallengeToken)
		assert.Empty(t, claims.Scopes, "challenge token should have no scopes")

		// Complete MFA verification
		code := generateTOTPCode(t, setupResp.Secret)
		verifyResp, err := client.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
			ChallengeToken: loginResp.MFAChallengeToken,
			Code:           code,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, verifyResp.AccessToken)

		// Full token should have scopes
		fullClaims := ExtractClaims(t, verifyResp.AccessToken)
		assert.NotEmpty(t, fullClaims.Scopes)
	})

	t.Run("MFA verification fails with invalid code", func(t *testing.T) {
		client := harness.NewClient(t)
		loginResp, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)

		_, err = client.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
			ChallengeToken: loginResp.MFAChallengeToken,
			Code:           "000000",
		})
		AssertAPIError(t, err, http.StatusUnauthorized, "should fail with invalid TOTP code")
	})

	t.Run("cannot access protected resources with challenge token", func(t *testing.T) {
		client := harness.NewClient(t)
		_, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)

		// Challenge token should not grant access to protected endpoints
		_, err = client.GetMFAStatus(ctx)
		AssertAPIError(t, err, http.StatusUnauthorized, "challenge token should not access protected resources")
	})
}

func TestMFABackupCodes(t *testing.T) {
	user := CreateVerifiedUser(t, "mfa-backup")
	ctx := context.Background()

	setupResp := enableMFA(t, user.Client)
	waitForNewTOTPWindow(t)

	t.Run("login with backup code", func(t *testing.T) {
		client := harness.NewClient(t)
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

func TestMFADisable(t *testing.T) {
	user := CreateVerifiedUser(t, "mfa-disable")
	ctx := context.Background()

	setupResp := enableMFA(t, user.Client)
	waitForNewTOTPWindow(t)

	t.Run("disable MFA with password and TOTP code", func(t *testing.T) {
		code := generateTOTPCode(t, setupResp.Secret)
		err := user.Client.DisableMFA(ctx, sdk.DisableMFARequest{
			Password: user.Password,
			Code:     code,
		})
		require.NoError(t, err)
	})

	t.Run("login without MFA after disabling", func(t *testing.T) {
		client := harness.NewClient(t)
		loginResp, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, loginResp.AccessToken, "should get access token directly without MFA")
		assert.Empty(t, loginResp.MFAChallengeToken, "should not get challenge token")
	})
}

func TestTOTPReplayPrevention(t *testing.T) {
	user := CreateVerifiedUser(t, "mfa-replay")
	ctx := context.Background()

	setupResp := enableMFA(t, user.Client)
	waitForNewTOTPWindow(t)

	t.Run("same code rejected twice within same window", func(t *testing.T) {
		client := harness.NewClient(t)
		loginResp, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)

		code := generateTOTPCode(t, setupResp.Secret)

		// First use succeeds
		_, err = client.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
			ChallengeToken: loginResp.MFAChallengeToken,
			Code:           code,
		})
		require.NoError(t, err)

		// Second login to get a new challenge token
		client2 := harness.NewClient(t)
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

func TestTrustedDevice(t *testing.T) {
	user := CreateVerifiedUser(t, "mfa-trusted")
	ctx := context.Background()

	setupResp := enableMFA(t, user.Client)
	waitForNewTOTPWindow(t)

	t.Run("trusted device skips MFA on subsequent login", func(t *testing.T) {
		client := harness.NewClient(t)

		// Login and verify MFA with trust_device=true
		loginResp, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)
		require.NotEmpty(t, loginResp.MFAChallengeToken)

		code := generateTOTPCode(t, setupResp.Secret)
		verifyResp, err := client.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
			ChallengeToken: loginResp.MFAChallengeToken,
			Code:           code,
			TrustDevice:    true,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, verifyResp.AccessToken)

		waitForNewTOTPWindow(t)

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

// Server-side input validation tests (bypass SDK client-side validation)

func TestMFAVerifyValidation(t *testing.T) {
	t.Run("missing challenge token", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1MFAVerify,
			`{"code":"123456"}`, "")
		assert.Equal(t, 400, status)
		assert.Contains(t, body, "challenge_token")
	})

	t.Run("missing code", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1MFAVerify,
			`{"challenge_token":"token"}`, "")
		assert.Equal(t, 400, status)
		assert.Contains(t, body, "code")
	})

	t.Run("invalid code length", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1MFAVerify,
			`{"challenge_token":"token","code":"1234"}`, "")
		assert.Equal(t, 400, status)
		assert.Contains(t, body, "code")
	})
}

func TestMFAEnableValidation(t *testing.T) {
	admin := CreateAdminUser(t, "val-mfa-enable")
	token := getAccessToken(t, admin)

	t.Run("missing code", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1MFAEnable, `{}`, token)
		assert.Equal(t, 400, status)
		assert.Contains(t, body, "code")
	})

	t.Run("wrong length code", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1MFAEnable,
			`{"code":"12345"}`, token)
		assert.Equal(t, 400, status)
		assert.Contains(t, body, "code")
	})
}

func TestMFADisableValidation(t *testing.T) {
	admin := CreateAdminUser(t, "val-mfa-disable")
	token := getAccessToken(t, admin)

	t.Run("missing password", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodDelete, sdk.RouteV1MFADisable,
			`{"code":"123456"}`, token)
		assert.Equal(t, 400, status)
		assert.Contains(t, body, "password")
	})

	t.Run("missing code", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodDelete, sdk.RouteV1MFADisable,
			`{"password":"test"}`, token)
		assert.Equal(t, 400, status)
		assert.Contains(t, body, "code")
	})
}
