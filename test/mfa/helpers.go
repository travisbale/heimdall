package mfa

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/setup"
)

// TOTPPeriod must match TOTP_PERIOD in docker-compose.yml (3s for fast tests)
const TOTPPeriod = 3

// GenerateTOTPCode generates a TOTP code using the 3-second test period
func GenerateTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period: TOTPPeriod,
		Digits: otp.DigitsSix,
	})
	require.NoError(t, err)
	return code
}

// WaitForNewTOTPWindow waits until the next TOTP window to avoid replay detection
func WaitForNewTOTPWindow(t *testing.T) {
	t.Helper()
	now := time.Now()
	msIntoWindow := now.UnixMilli() % (TOTPPeriod * 1000)
	waitTime := time.Duration(TOTPPeriod*1000-msIntoWindow+100) * time.Millisecond
	time.Sleep(waitTime)
}

// EnableMFA completes setup + enable in a single call
func EnableMFA(t *testing.T, client *sdk.HTTPClient) *sdk.MFASetupResponse {
	t.Helper()

	setupResp, err := client.SetupMFA(context.Background())
	require.NoError(t, err)

	code := GenerateTOTPCode(t, setupResp.Secret)
	err = client.EnableMFA(context.Background(), sdk.EnableMFARequest{Code: code})
	require.NoError(t, err)

	return setupResp
}

// VerifyMFACodeWithSecret generates a TOTP code and verifies MFA
func VerifyMFACodeWithSecret(t *testing.T, client *sdk.HTTPClient, challengeToken, secret string) *sdk.LoginResponse {
	t.Helper()

	code := GenerateTOTPCode(t, secret)
	resp, err := client.VerifyMFACode(context.Background(), sdk.VerifyMFACodeRequest{
		ChallengeToken: challengeToken,
		Code:           code,
	})
	require.NoError(t, err)
	return resp
}

// CreateUserWithMFARequiredRole creates a user assigned to an MFA-required role (not logged in)
func CreateUserWithMFARequiredRole(t *testing.T, admin *setup.UserClient, name string) *setup.UserClient {
	t.Helper()

	role, err := admin.Client.CreateRole(context.Background(), sdk.CreateRoleRequest{
		Name:        fmt.Sprintf("MFA Required %d", time.Now().UnixNano()),
		Description: "Role that requires MFA",
		MFARequired: true,
	})
	require.NoError(t, err)

	return setup.CreateUserInTenantWithRoles(t, admin, name, []uuid.UUID{role.ID})
}
