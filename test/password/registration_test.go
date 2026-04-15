package password

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/assertions"
	"github.com/travisbale/heimdall/test/_util/database"
	"github.com/travisbale/heimdall/test/_util/request"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestRegistration(t *testing.T) {
	t.Parallel()
	client := setup.CreateClient(t)
	email, password := setup.GenerateTestCredentials(t, "register")

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
		token := database.GetVerificationToken(t, email)

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
		assertions.AssertAPIError(t, err, http.StatusConflict, "duplicate registration should fail")
	})
}

func TestRegistrationValidation(t *testing.T) {
	t.Parallel()
	t.Run("missing email", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1Register,
			`{"first_name":"Test","last_name":"User"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})

	t.Run("invalid email format", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1Register,
			`{"email":"bad","first_name":"Test","last_name":"User"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "email")
	})

	t.Run("missing first name", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1Register,
			`{"email":"user@example.com","last_name":"User"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "first name")
	})

	t.Run("missing last name", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1Register,
			`{"email":"user@example.com","first_name":"Test"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "last name")
	})
}

func TestVerifyEmailValidation(t *testing.T) {
	t.Parallel()
	t.Run("missing token", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1VerifyEmail,
			`{"password":"Xe9#mK2pLq!vR4"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "token")
	})

	t.Run("missing password", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1VerifyEmail,
			`{"token":"abc123"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "password")
	})

	t.Run("weak password", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1VerifyEmail,
			`{"token":"abc123","password":"short"}`, "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "password")
	})
}
