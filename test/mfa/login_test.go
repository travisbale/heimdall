package mfa

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/assertions"
	testjwt "github.com/travisbale/heimdall/test/_util/jwt"
	"github.com/travisbale/heimdall/test/_util/request"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestMFALogin(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "mfa-login")
	ctx := context.Background()

	setupResp := EnableMFA(t, user.Client)
	WaitForNewTOTPWindow(t)

	t.Run("complete MFA login flow", func(t *testing.T) {
		client := setup.CreateClient(t)

		// Password auth returns MFA challenge token, not access token
		loginResp, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, loginResp.MFAChallengeToken)
		assert.Empty(t, loginResp.AccessToken, "should not receive access token before MFA")

		// Verify challenge token has correct audience and no scopes
		claims := testjwt.ExtractMFAChallengeClaims(t, loginResp.MFAChallengeToken)
		assert.Empty(t, claims.Scopes, "challenge token should have no scopes")

		// Complete MFA verification
		code := GenerateTOTPCode(t, setupResp.Secret)
		verifyResp, err := client.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
			ChallengeToken: loginResp.MFAChallengeToken,
			Code:           code,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, verifyResp.AccessToken)

		// Full token should have scopes
		fullClaims := testjwt.ExtractClaims(t, verifyResp.AccessToken)
		assert.NotEmpty(t, fullClaims.Scopes)
	})

	t.Run("MFA verification fails with invalid code", func(t *testing.T) {
		client := setup.CreateClient(t)
		loginResp, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)

		_, err = client.VerifyMFACode(ctx, sdk.VerifyMFACodeRequest{
			ChallengeToken: loginResp.MFAChallengeToken,
			Code:           "000000",
		})
		assertions.AssertAPIError(t, err, http.StatusUnauthorized, "should fail with invalid TOTP code")
	})

	t.Run("cannot access protected resources with challenge token", func(t *testing.T) {
		client := setup.CreateClient(t)
		_, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)

		// Challenge token should not grant access to protected endpoints
		_, err = client.GetMFAStatus(ctx)
		assertions.AssertAPIError(t, err, http.StatusUnauthorized, "challenge token should not access protected resources")
	})
}

func TestMFAVerifyValidation(t *testing.T) {
	t.Parallel()
	t.Run("missing challenge token", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1MFAVerify,
			`{"code":"123456"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "challenge_token")
	})

	t.Run("missing code", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1MFAVerify,
			`{"challenge_token":"token"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "code")
	})

	t.Run("invalid code length", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1MFAVerify,
			`{"challenge_token":"token","code":"1234"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "code")
	})
}
