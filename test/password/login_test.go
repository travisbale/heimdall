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
	"github.com/travisbale/heimdall/test/_util/assertions"
	"github.com/travisbale/heimdall/test/_util/request"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestLogin(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "login")
	client := setup.CreateClient(t)

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
		assertions.AssertAPIError(t, err, http.StatusUnauthorized, "login should fail with invalid email")
	})

	t.Run("wrong password returns 401", func(t *testing.T) {
		_, err := client.Login(context.Background(), sdk.LoginRequest{
			Email:    user.Email,
			Password: "WrongPassword123!",
		})
		assertions.AssertAPIError(t, err, http.StatusUnauthorized, "login should fail with wrong password")
	})
}

func TestLoginValidation(t *testing.T) {
	t.Parallel()
	t.Run("missing email", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1Login, `{"password":"test"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})

	t.Run("invalid email format", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1Login, `{"email":"not-email","password":"test"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})

	t.Run("missing password", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1Login, `{"email":"user@example.com"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "password")
	})

	t.Run("malformed JSON", func(t *testing.T) {
		status, _ := request.RawRequest(t, http.MethodPost, sdk.RouteV1Login, `{bad json`, "")
		assert.Equal(t, http.StatusBadRequest, status)
	})
}

func TestAuthRequired(t *testing.T) {
	t.Parallel()
	t.Run("MFA setup", func(t *testing.T) {
		status, _ := request.RawRequest(t, http.MethodPost, sdk.RouteV1MFASetup, `{}`, "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("MFA status", func(t *testing.T) {
		status, _ := request.RawRequest(t, http.MethodGet, sdk.RouteV1MFAStatus, "", "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("list sessions", func(t *testing.T) {
		status, _ := request.RawRequest(t, http.MethodGet, sdk.RouteV1Sessions, "", "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("list roles", func(t *testing.T) {
		status, _ := request.RawRequest(t, http.MethodGet, sdk.RouteV1Roles, "", "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("list permissions", func(t *testing.T) {
		status, _ := request.RawRequest(t, http.MethodGet, sdk.RouteV1Permissions, "", "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}
