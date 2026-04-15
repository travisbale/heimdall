package oidc

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	util "github.com/travisbale/heimdall/test/_util"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestSSOFlow(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "sso-flow")
	ctx := context.Background()

	config := util.LoadConfig()

	_, err := admin.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:             "Acme Corp SSO",
		IssuerURL:                config.OIDCMockInternalURL + "/default",
		ClientID:                 "test-client-id",
		ClientSecret:             "test-client-secret",
		Scopes:                   []string{"openid", "email", "profile"},
		Enabled:                  true,
		AllowedDomains:           []string{"acmecorp.com"},
		AutoCreateUsers:          true,
		RequireEmailVerification: false,
	})
	require.NoError(t, err)

	t.Run("complete SSO flow with new user", func(t *testing.T) {
		ssoEmail := fmt.Sprintf("alice-%d@acmecorp.com", time.Now().UnixNano())

		// Initiate SSO login
		authResp, err := admin.Client.SSOLogin(ctx, sdk.SSOLoginRequest{
			Email: ssoEmail,
		})
		require.NoError(t, err)
		require.NotEmpty(t, authResp.AuthorizationURL)

		// Follow the OAuth flow through the mock OIDC server
		tokenResp := FollowOAuthFlow(t, authResp.AuthorizationURL)
		assert.NotEmpty(t, tokenResp.AccessToken, "should receive access token")
		assert.Equal(t, "Bearer", tokenResp.TokenType)
	})

	t.Run("returning SSO user authenticates successfully", func(t *testing.T) {
		// The mock default issuer always returns mockuser@example.com
		// but domain matching is on the SSO email, not the IdP email
		ssoEmail := fmt.Sprintf("returning-%d@acmecorp.com", time.Now().UnixNano())

		// First login
		authResp, err := admin.Client.SSOLogin(ctx, sdk.SSOLoginRequest{Email: ssoEmail})
		require.NoError(t, err)
		FollowOAuthFlow(t, authResp.AuthorizationURL)

		// Second login — same user should authenticate
		authResp, err = admin.Client.SSOLogin(ctx, sdk.SSOLoginRequest{Email: ssoEmail})
		require.NoError(t, err)
		tokenResp := FollowOAuthFlow(t, authResp.AuthorizationURL)
		assert.NotEmpty(t, tokenResp.AccessToken)
	})
}

func TestSSOAutoProvisioningDisabled(t *testing.T) {
	t.Parallel()
	admin := setup.CreateAdminUser(t, "sso-no-autoprov")
	ctx := context.Background()

	config := util.LoadConfig()

	_, err := admin.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:             "Restricted Corp SSO",
		IssuerURL:                config.OIDCMockInternalURL + "/github",
		ClientID:                 "test-client-id",
		ClientSecret:             "test-client-secret",
		Scopes:                   []string{"openid", "email", "profile"},
		Enabled:                  true,
		AllowedDomains:           []string{"users.noreply.github.com"},
		AutoCreateUsers:          false,
		RequireEmailVerification: false,
	})
	require.NoError(t, err)

	t.Run("new user rejected when auto-provisioning disabled", func(t *testing.T) {
		ssoEmail := "githubuser@users.noreply.github.com"
		authResp, err := admin.Client.SSOLogin(ctx, sdk.SSOLoginRequest{Email: ssoEmail})
		require.NoError(t, err)
		require.NotEmpty(t, authResp.AuthorizationURL)

		resp := CompleteOAuthFlow(t, authResp.AuthorizationURL)
		defer func() { _ = resp.Body.Close() }()
		assert.True(t, resp.StatusCode >= 400,
			"should reject new user when auto-provisioning disabled, got %d", resp.StatusCode)
	})
}
