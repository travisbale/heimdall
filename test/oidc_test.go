//go:build integration

package test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

// newMockOIDCServer creates a minimal OIDC discovery server for provider CRUD tests.
// Returns the server (caller must defer Close) and its issuer URL.
func newMockOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	var issuerURL string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuerURL,
			"authorization_endpoint": issuerURL + "/authorize",
			"token_endpoint":         issuerURL + "/token",
			"userinfo_endpoint":      issuerURL + "/userinfo",
			"jwks_uri":               issuerURL + "/jwks",
		})
	})

	server := httptest.NewServer(mux)
	issuerURL = server.URL
	return server
}

func TestOIDCProviderCRUD(t *testing.T) {
	admin := CreateAdminUser(t, "oidc-crud")
	ctx := context.Background()

	oidcServer := newMockOIDCServer(t)
	defer oidcServer.Close()

	t.Run("create manual OIDC provider", func(t *testing.T) {
		provider, err := admin.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
			ProviderName:             "Test Okta",
			IssuerURL:                oidcServer.URL,
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
		assert.Equal(t, oidcServer.URL, provider.IssuerURL)
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

	// Send raw HTTP requests to bypass SDK client-side validation
	// and test the server's own validation responses
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
