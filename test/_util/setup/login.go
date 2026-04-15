package setup

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

// LoginUser logs in and returns the response. Fails the test on error.
func LoginUser(t *testing.T, client *sdk.HTTPClient, email, password string) *sdk.LoginResponse {
	t.Helper()

	resp, err := client.Login(context.Background(), sdk.LoginRequest{
		Email:    email,
		Password: password,
	})
	require.NoError(t, err, "login should succeed")

	return resp
}

// GetAccessToken logs in with a fresh client and returns the raw access token
func GetAccessToken(t *testing.T, user *UserClient) string {
	t.Helper()
	client := CreateClient(t)
	resp := LoginUser(t, client, user.Email, user.Password)
	return resp.AccessToken
}
