//go:build integration

package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

func TestOIDCProviderCRUD(t *testing.T) {
	admin := CreateAdminUser(t, "oidc-crud")
	ctx := context.Background()

	// Use the mock OIDC server's default issuer for provider CRUD tests
	issuerURL := harness.OIDCMockURL + "/default"

	t.Run("create manual OIDC provider", func(t *testing.T) {
		provider, err := admin.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
			ProviderName:             "Test Okta",
			IssuerURL:                issuerURL,
			ClientID:                 "test-client-id",
			ClientSecret:             "test-client-secret",
			Scopes:                   []string{"openid", "profile", "email"},
			Enabled:                  true,
			AllowedDomains:           []string{"example.com"},
			AutoCreateUsers:          true,
			RequireEmailVerification: true,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, provider.ID)
		assert.Equal(t, "Test Okta", provider.ProviderName)
		assert.Equal(t, issuerURL, provider.IssuerURL)
		assert.Equal(t, "test-client-id", provider.ClientID)
		assert.True(t, provider.Enabled)
		assert.Equal(t, []string{"example.com"}, provider.AllowedDomains)
		assert.True(t, provider.AutoCreateUsers)
		assert.True(t, provider.RequireEmailVerification)
		assert.Equal(t, sdk.OIDCRegistrationMethodManual, provider.RegistrationMethod)

		t.Run("get provider by ID", func(t *testing.T) {
			got, err := admin.Client.GetOIDCProvider(ctx, sdk.GetOIDCProviderRequest{
				ProviderID: provider.ID,
			})
			require.NoError(t, err)
			assert.Equal(t, provider.ID, got.ID)
			assert.Equal(t, "Test Okta", got.ProviderName)
		})

		t.Run("list providers includes created provider", func(t *testing.T) {
			list, err := admin.Client.ListOIDCProviders(ctx)
			require.NoError(t, err)

			found := false
			for _, p := range list.Providers {
				if p.ID == provider.ID {
					found = true
				}
			}
			assert.True(t, found, "created provider should appear in list")
		})

		t.Run("update provider", func(t *testing.T) {
			newName := "Updated Okta"
			disabled := false
			updated, err := admin.Client.UpdateOIDCProvider(ctx, sdk.UpdateOIDCProviderRequest{
				ProviderID:   provider.ID,
				ProviderName: &newName,
				Enabled:      &disabled,
			})
			require.NoError(t, err)
			assert.Equal(t, "Updated Okta", updated.ProviderName)
			assert.False(t, updated.Enabled)
		})

		t.Run("delete provider", func(t *testing.T) {
			err := admin.Client.DeleteOIDCProvider(ctx, sdk.DeleteOIDCProviderRequest{
				ProviderID: provider.ID,
			})
			require.NoError(t, err)

			_, err = admin.Client.GetOIDCProvider(ctx, sdk.GetOIDCProviderRequest{
				ProviderID: provider.ID,
			})
			assert.Error(t, err, "deleted provider should not be found")
		})
	})
}

func TestOIDCProviderValidation(t *testing.T) {
	admin := CreateAdminUser(t, "oidc-validation")

	token := getAccessToken(t, admin)
	post := func(t *testing.T, body string) (int, string) {
		t.Helper()
		return RawRequest(t, http.MethodPost, sdk.RouteV1OAuthProviders, body, token)
	}

	t.Run("missing provider name", func(t *testing.T) {
		status, body := post(t, `{
			"issuer_url": "https://test.okta.com",
			"client_id": "test-client-id",
			"client_secret": "test-client-secret",
			"allowed_domains": ["example.com"]
		}`)
		assert.Equal(t, 400, status)
		assert.Contains(t, body, "provider_name")
	})

	t.Run("missing allowed domains", func(t *testing.T) {
		status, body := post(t, `{
			"provider_name": "Test Provider",
			"issuer_url": "https://test.okta.com",
			"client_id": "test-client-id",
			"client_secret": "test-client-secret"
		}`)
		assert.Equal(t, 400, status)
		assert.Contains(t, body, "allowed domain")
	})

	t.Run("client ID without secret", func(t *testing.T) {
		status, body := post(t, `{
			"provider_name": "Test Provider",
			"issuer_url": "https://test.okta.com",
			"client_id": "test-client-id",
			"allowed_domains": ["example.com"]
		}`)
		assert.Equal(t, 400, status)
		assert.Contains(t, body, "client_secret")
	})

	t.Run("non-HTTPS issuer URL rejected", func(t *testing.T) {
		status, body := post(t, `{
			"provider_name": "Test Provider",
			"issuer_url": "http://not-secure.example.com",
			"client_id": "test-client-id",
			"client_secret": "test-client-secret",
			"allowed_domains": ["example.com"]
		}`)
		assert.Equal(t, 400, status)
		assert.Contains(t, body, "HTTPS")
	})
}

func TestListSupportedOIDCProviderTypes(t *testing.T) {
	client := harness.NewClient(t)
	ctx := context.Background()

	resp, err := client.ListSupportedProviders(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Providers, "should list supported provider types")

	names := make(map[sdk.OIDCProviderType]bool)
	for _, p := range resp.Providers {
		names[p.Type] = true
	}
	assert.True(t, names[sdk.OIDCProviderTypeGoogle], "should include Google")
	assert.True(t, names[sdk.OIDCProviderTypeMicrosoft], "should include Microsoft")
	assert.True(t, names[sdk.OIDCProviderTypeGitHub], "should include GitHub")
}

func TestSSOFlow(t *testing.T) {
	admin := CreateAdminUser(t, "sso-flow")
	ctx := context.Background()

	// Create OIDC provider pointing at the mock server's default issuer
	_, err := admin.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:             "Acme Corp SSO",
		IssuerURL:                harness.OIDCMockURL + "/default",
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
		tokenResp := followOAuthFlow(t, authResp.AuthorizationURL)
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
		followOAuthFlow(t, authResp.AuthorizationURL)

		// Second login — same user should authenticate
		authResp, err = admin.Client.SSOLogin(ctx, sdk.SSOLoginRequest{Email: ssoEmail})
		require.NoError(t, err)
		tokenResp := followOAuthFlow(t, authResp.AuthorizationURL)
		assert.NotEmpty(t, tokenResp.AccessToken)
	})
}

func TestSSOAutoProvisioningDisabled(t *testing.T) {
	admin := CreateAdminUser(t, "sso-no-autoprov")
	ctx := context.Background()

	// Create OIDC provider with auto-provisioning disabled
	_, err := admin.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:             "Restricted Corp SSO",
		IssuerURL:                harness.OIDCMockURL + "/github",
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

		resp := completeOAuthFlow(t, authResp.AuthorizationURL)
		defer func() { _ = resp.Body.Close() }()
		assert.True(t, resp.StatusCode >= 400,
			"should reject new user when auto-provisioning disabled, got %d", resp.StatusCode)
	})
}

func TestIndividualOAuthLogin(t *testing.T) {
	client := harness.NewClient(t)
	ctx := context.Background()

	t.Run("initiate Google OAuth", func(t *testing.T) {
		resp, err := client.OAuthLogin(ctx, sdk.OIDCLoginRequest{
			ProviderType: sdk.OIDCProviderTypeGoogle,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AuthorizationURL)
		assert.Contains(t, resp.AuthorizationURL, "google")
	})

	t.Run("initiate Microsoft OAuth", func(t *testing.T) {
		resp, err := client.OAuthLogin(ctx, sdk.OIDCLoginRequest{
			ProviderType: sdk.OIDCProviderTypeMicrosoft,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AuthorizationURL)
		assert.Contains(t, resp.AuthorizationURL, "microsoft")
	})

	t.Run("initiate GitHub OAuth", func(t *testing.T) {
		resp, err := client.OAuthLogin(ctx, sdk.OIDCLoginRequest{
			ProviderType: sdk.OIDCProviderTypeGitHub,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AuthorizationURL)
		assert.Contains(t, resp.AuthorizationURL, "github")
	})
}

// completeOAuthFlow follows the OAuth authorization flow through the mock OIDC server,
// intercepts the frontend callback redirect, extracts the code and state,
// and calls the backend API directly. Returns the raw backend response.
func completeOAuthFlow(t *testing.T, authorizationURL string) *http.Response {
	t.Helper()

	// Intercept the redirect to the frontend callback URL (/oauth/callback)
	// since there's no frontend running in tests
	var callbackURL string
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Path == "/oauth/callback" {
				callbackURL = req.URL.String()
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Get(authorizationURL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.NotEmpty(t, callbackURL, "should have been redirected to callback URL")

	// Extract code and state, then call the backend directly
	parsed, err := url.Parse(callbackURL)
	require.NoError(t, err)
	code := parsed.Query().Get("code")
	state := parsed.Query().Get("state")
	require.NotEmpty(t, code, "callback should contain authorization code")
	require.NotEmpty(t, state, "callback should contain state")

	backendURL := fmt.Sprintf("%s%s?code=%s&state=%s",
		harness.BaseURL, sdk.RouteV1OAuthCallback,
		url.QueryEscape(code), url.QueryEscape(state))

	backendResp, err := http.Get(backendURL)
	require.NoError(t, err)

	return backendResp
}

// followOAuthFlow completes the OAuth flow and returns the parsed token response
func followOAuthFlow(t *testing.T, authorizationURL string) *sdk.LoginResponse {
	t.Helper()

	resp := completeOAuthFlow(t, authorizationURL)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode, "OAuth callback should return 200")

	var tokenResp sdk.LoginResponse
	err := json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err, "should decode token response")

	return &tokenResp
}
