package mfa

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/request"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestMFADisable(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "mfa-disable")
	ctx := context.Background()

	setupResp := EnableMFA(t, user.Client)
	WaitForNewTOTPWindow(t)

	t.Run("disable MFA with password and TOTP code", func(t *testing.T) {
		code := GenerateTOTPCode(t, setupResp.Secret)
		err := user.Client.DisableMFA(ctx, sdk.DisableMFARequest{
			Password: user.Password,
			Code:     code,
		})
		require.NoError(t, err)
	})

	t.Run("login without MFA after disabling", func(t *testing.T) {
		client := setup.CreateClient(t)
		loginResp, err := client.Login(ctx, sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, loginResp.AccessToken, "should get access token directly without MFA")
		assert.Empty(t, loginResp.MFAChallengeToken, "should not get challenge token")
	})
}

func TestMFADisableValidation(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "val-mfa-disable")
	token := setup.GetAccessToken(t, admin)

	t.Run("missing password", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodDelete, sdk.RouteV1MFADisable,
			`{"code":"123456"}`, token)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "password")
	})

	t.Run("missing code", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodDelete, sdk.RouteV1MFADisable,
			`{"password":"test"}`, token)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "code")
	})

}
