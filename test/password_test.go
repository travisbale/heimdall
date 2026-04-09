//go:build integration

package test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

func TestHealthCheck(t *testing.T) {
	t.Parallel()
	client := harness.NewClient(t)

	err := client.Health(context.Background())
	require.NoError(t, err, "health check should succeed")
}

func TestRegistration(t *testing.T) {
	t.Parallel()
	client := harness.NewClient(t)
	email, password := GenerateTestCredentials(t, "register")

	t.Run("register user", func(t *testing.T) {
		resp, err := client.Register(context.Background(), sdk.RegisterRequest{
			Email:     email,
			FirstName: "Test",
			LastName:  "User",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Message)
		assert.Equal(t, email, resp.Email)
	})

	t.Run("cannot login before verification", func(t *testing.T) {
		_, err := client.Login(context.Background(), sdk.LoginRequest{
			Email:    email,
			Password: password,
		})
		assert.Error(t, err, "login should fail for unverified user")
	})

	t.Run("verify email and set password", func(t *testing.T) {
		token := GetVerificationToken(t, harness.DB, email)

		resp, err := client.VerifyEmail(context.Background(), sdk.VerifyEmailRequest{
			Token:    token,
			Password: password,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
	})

	t.Run("can login after verification", func(t *testing.T) {
		resp, err := client.Login(context.Background(), sdk.LoginRequest{
			Email:    email,
			Password: password,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
	})

	t.Run("cannot register duplicate email", func(t *testing.T) {
		_, err := client.Register(context.Background(), sdk.RegisterRequest{
			Email:     email,
			FirstName: "Test",
			LastName:  "User",
		})
		AssertAPIError(t, err, http.StatusConflict, "duplicate registration should fail")
	})
}

func TestLogin(t *testing.T) {
	t.Parallel()
	user := CreateVerifiedUser(t, "login")
	client := harness.NewClient(t)

	t.Run("successful login", func(t *testing.T) {
		resp, err := client.Login(context.Background(), sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Greater(t, resp.ExpiresIn, 0)
	})

	t.Run("invalid email returns 401", func(t *testing.T) {
		_, err := client.Login(context.Background(), sdk.LoginRequest{
			Email:    fmt.Sprintf("nonexistent-%d@test.example.com", time.Now().UnixNano()),
			Password: "SomePassword123!",
		})
		AssertAPIError(t, err, http.StatusUnauthorized, "login should fail with invalid email")
	})

	t.Run("wrong password returns 401", func(t *testing.T) {
		_, err := client.Login(context.Background(), sdk.LoginRequest{
			Email:    user.Email,
			Password: "WrongPassword123!",
		})
		AssertAPIError(t, err, http.StatusUnauthorized, "login should fail with wrong password")
	})
}

func TestPasswordReset(t *testing.T) {
	t.Parallel()
	user := CreateVerifiedUser(t, "reset")
	client := harness.NewClient(t)

	t.Run("request password reset", func(t *testing.T) {
		_, err := client.ForgotPassword(context.Background(), sdk.ForgotPasswordRequest{
			Email: user.Email,
		})
		require.NoError(t, err)
	})

	t.Run("reset password with token", func(t *testing.T) {
		token := GetPasswordResetToken(t, harness.DB, user.Email)
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

func TestAccountLockout(t *testing.T) {
	t.Parallel()
	user := CreateVerifiedUser(t, "lockout")
	client := harness.NewClient(t)

	// Clear any prior login attempts
	ClearLoginAttempts(t, harness.DB, user.Email)

	t.Run("account locks after repeated failures", func(t *testing.T) {
		// Attempt 5 failed logins to trigger lockout
		for i := 0; i < 5; i++ {
			_, err := client.Login(context.Background(), sdk.LoginRequest{
				Email:    user.Email,
				Password: "WrongPassword123!",
			})
			assert.Error(t, err)
		}

		// Next attempt should be locked out
		_, err := client.Login(context.Background(), sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		AssertAPIError(t, err, http.StatusTooManyRequests, "account should be locked after 5 failed attempts")
	})
}

func TestLogout(t *testing.T) {
	t.Parallel()
	user := CreateVerifiedUser(t, "logout")

	t.Run("logout invalidates refresh token", func(t *testing.T) {
		_, err := user.Client.Logout(context.Background())
		require.NoError(t, err)

		// Refresh should fail after logout
		_, err = user.Client.RefreshToken(context.Background())
		assert.Error(t, err, "refresh should fail after logout")
	})
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()
	user := CreateVerifiedUser(t, "refresh")

	t.Run("refresh returns new access token", func(t *testing.T) {
		resp, err := user.Client.RefreshToken(context.Background())
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
	})
}

// Server-side input validation tests (bypass SDK client-side validation)

func TestLoginValidation(t *testing.T) {
	t.Parallel()
	t.Run("missing email", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1Login, `{"password":"test"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})

	t.Run("invalid email format", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1Login, `{"email":"not-email","password":"test"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})

	t.Run("missing password", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1Login, `{"email":"user@example.com"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "password")
	})

	t.Run("malformed JSON", func(t *testing.T) {
		status, _ := RawRequest(t, http.MethodPost, sdk.RouteV1Login, `{bad json`, "")
		assert.Equal(t, http.StatusBadRequest, status)
	})
}

func TestRegistrationValidation(t *testing.T) {
	t.Parallel()
	t.Run("missing email", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1Register,
			`{"first_name":"Test","last_name":"User"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})

	t.Run("invalid email format", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1Register,
			`{"email":"bad","first_name":"Test","last_name":"User"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})

	t.Run("missing first name", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1Register,
			`{"email":"user@example.com","last_name":"User"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "first name")
	})

	t.Run("missing last name", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1Register,
			`{"email":"user@example.com","first_name":"Test"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "last name")
	})
}

func TestVerifyEmailValidation(t *testing.T) {
	t.Parallel()
	t.Run("missing token", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1VerifyEmail,
			`{"password":"Xe9#mK2pLq!vR4"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "token")
	})

	t.Run("missing password", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1VerifyEmail,
			`{"token":"abc123"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "password")
	})

	t.Run("weak password", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1VerifyEmail,
			`{"token":"abc123","password":"short"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "password")
	})
}

func TestForgotPasswordValidation(t *testing.T) {
	t.Parallel()
	t.Run("missing email", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1ForgotPassword, `{}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})

	t.Run("invalid email format", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1ForgotPassword,
			`{"email":"not-email"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})
}

func TestResetPasswordValidation(t *testing.T) {
	t.Parallel()
	t.Run("missing token", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1ResetPassword,
			`{"new_password":"Xe9#mK2pLq!vR4"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "token")
	})

	t.Run("weak password", func(t *testing.T) {
		status, body := RawRequest(t, http.MethodPost, sdk.RouteV1ResetPassword,
			`{"token":"abc123","new_password":"weak"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "password")
	})
}

func TestAuthRequired(t *testing.T) {
	t.Parallel()
	t.Run("MFA setup", func(t *testing.T) {
		status, _ := RawRequest(t, http.MethodPost, sdk.RouteV1MFASetup, `{}`, "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("MFA status", func(t *testing.T) {
		status, _ := RawRequest(t, http.MethodGet, sdk.RouteV1MFAStatus, "", "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("list sessions", func(t *testing.T) {
		status, _ := RawRequest(t, http.MethodGet, sdk.RouteV1Sessions, "", "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("list roles", func(t *testing.T) {
		status, _ := RawRequest(t, http.MethodGet, sdk.RouteV1Roles, "", "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("list permissions", func(t *testing.T) {
		status, _ := RawRequest(t, http.MethodGet, sdk.RouteV1Permissions, "", "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}
