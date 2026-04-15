package password

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/database"
	"github.com/travisbale/heimdall/test/_util/request"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestPasswordReset(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "reset")
	client := setup.CreateClient(t)

	t.Run("request password reset", func(t *testing.T) {
		_, err := client.ForgotPassword(context.Background(), sdk.ForgotPasswordRequest{
			Email: user.Email,
		})
		require.NoError(t, err)
	})

	t.Run("reset password with token", func(t *testing.T) {
		token := database.GetPasswordResetToken(t, user.Email)
		newPassword := fmt.Sprintf("NewPass-%d!", time.Now().UnixNano())

		_, err := client.ResetPassword(context.Background(), sdk.ResetPasswordRequest{
			Token:       token,
			NewPassword: newPassword,
		})
		require.NoError(t, err)

		// Login with new password
		resp, err := client.Login(context.Background(), sdk.LoginRequest{
			Email:    user.Email,
			Password: newPassword,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
	})
}

func TestForgotPasswordValidation(t *testing.T) {
	t.Parallel()
	t.Run("missing email", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1ForgotPassword, `{}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})

	t.Run("invalid email format", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1ForgotPassword,
			`{"email":"not-email"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})
}

func TestResetPasswordValidation(t *testing.T) {
	t.Parallel()
	t.Run("missing token", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1ResetPassword,
			`{"new_password":"Xe9#mK2pLq!vR4"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "token")
	})

	t.Run("weak password", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1ResetPassword,
			`{"token":"abc123","new_password":"weak"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "password")
	})
}
