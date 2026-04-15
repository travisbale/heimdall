package isolation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	util "github.com/travisbale/heimdall/test/_util"
)

func TestTenantIsolation_OIDCLinks(t *testing.T) {
	t.Parallel()
	tenantA := createAdminUser(t, "iso-links-a")
	tenantB := createAdminUser(t, "iso-links-b")
	ctx := context.Background()

	// Each tenant creates their own OIDC provider
	// Hardcode the Docker hostname since heimdall does OIDC discovery from inside the container
	providerA, err := tenantA.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:    "Tenant A Azure",
		IssuerURL:       util.LoadConfig().OIDCMockInternalURL + "/default",
		ClientID:        "a-azure-client",
		ClientSecret:    "a-azure-secret",
		AllowedDomains:  []string{"companya.com"},
		Enabled:         true,
		AutoCreateUsers: true,
	})
	require.NoError(t, err)

	providerB, err := tenantB.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:    "Tenant B Azure",
		IssuerURL:       util.LoadConfig().OIDCMockInternalURL + "/default",
		ClientID:        "b-azure-client",
		ClientSecret:    "b-azure-secret",
		AllowedDomains:  []string{"companyb.com"},
		Enabled:         true,
		AutoCreateUsers: true,
	})
	require.NoError(t, err)

	t.Run("OIDC links isolated via provider foreign keys", func(t *testing.T) {
		// Each tenant can only see their own provider
		respA, err := tenantA.Client.ListOIDCProviders(ctx)
		require.NoError(t, err)
		require.Len(t, respA.Providers, 1)
		assert.Equal(t, providerA.ID, respA.Providers[0].ID)

		respB, err := tenantB.Client.ListOIDCProviders(ctx)
		require.NoError(t, err)
		require.Len(t, respB.Providers, 1)
		assert.Equal(t, providerB.ID, respB.Providers[0].ID)
	})

	t.Run("cross-tenant provider not visible", func(t *testing.T) {
		providersA, err := tenantA.Client.ListOIDCProviders(ctx)
		require.NoError(t, err)
		for _, p := range providersA.Providers {
			assert.NotEqual(t, providerB.ID, p.ID, "tenant A should not see tenant B provider")
		}

		providersB, err := tenantB.Client.ListOIDCProviders(ctx)
		require.NoError(t, err)
		for _, p := range providersB.Providers {
			assert.NotEqual(t, providerA.ID, p.ID, "tenant B should not see tenant A provider")
		}
	})
}
