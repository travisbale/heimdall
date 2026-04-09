//go:build integration

package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

func TestHealthCheck(t *testing.T) {
	client := harness.NewClient(t)

	err := client.Health(context.Background())
	require.NoError(t, err, "health check should succeed")
}

func TestRegistration(t *testing.T) {
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
		AssertStatus409(t, err, "duplicate registration should fail")
	})
}

func TestLogin(t *testing.T) {
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
		AssertStatus401(t, err, "login should fail with invalid email")
	})

	t.Run("wrong password returns 401", func(t *testing.T) {
		_, err := client.Login(context.Background(), sdk.LoginRequest{
			Email:    user.Email,
			Password: "WrongPassword123!",
		})
		AssertStatus401(t, err, "login should fail with wrong password")
	})
}

func TestPasswordReset(t *testing.T) {
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
		AssertStatus429(t, err, "account should be locked after 5 failed attempts")
	})
}

func TestLogout(t *testing.T) {
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
	user := CreateVerifiedUser(t, "refresh")

	t.Run("refresh returns new access token", func(t *testing.T) {
		resp, err := user.Client.RefreshToken(context.Background())
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
	})
}
