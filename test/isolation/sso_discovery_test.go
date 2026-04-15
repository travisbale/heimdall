package isolation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	util "github.com/travisbale/heimdall/test/_util"
)

func TestTenantIsolation_SSODiscovery(t *testing.T) {
	t.Parallel()
	tenantA := createAdminUser(t, "iso-sso-a")
	tenantB := createAdminUser(t, "iso-sso-b")
	ctx := context.Background()

	oidcMockInternalURL := util.LoadConfig().OIDCMockInternalURL

	// Both tenants configure SSO for different domains
	_, err := tenantA.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:    "Tenant A SSO",
		IssuerURL:       oidcMockInternalURL + "/default",
		ClientID:        "a-client",
		ClientSecret:    "a-secret",
		AllowedDomains:  []string{"tenanta-sso.com"},
		Enabled:         true,
		AutoCreateUsers: true,
	})
	require.NoError(t, err)

	_, err = tenantB.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:    "Tenant B SSO",
		IssuerURL:       oidcMockInternalURL + "/default",
		ClientID:        "b-client",
		ClientSecret:    "b-secret",
		AllowedDomains:  []string{"tenantb-sso.com"},
		Enabled:         true,
		AutoCreateUsers: true,
	})
	require.NoError(t, err)

	t.Run("SSO discovers correct tenant provider", func(t *testing.T) {
		// Tenant A's domain should work
		resp, err := tenantA.Client.SSOLogin(ctx, sdk.SSOLoginRequest{
			Email: "user@tenanta-sso.com",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AuthorizationURL)
	})

	t.Run("SSO for unconfigured domain fails", func(t *testing.T) {
		_, err := tenantA.Client.SSOLogin(ctx, sdk.SSOLoginRequest{
			Email: "user@no-sso-configured.com",
		})
		assert.Error(t, err, "unconfigured domain should fail")
	})
}
