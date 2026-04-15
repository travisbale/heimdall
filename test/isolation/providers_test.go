package isolation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	util "github.com/travisbale/heimdall/test/_util"
)

func TestTenantIsolation_OIDCProviders(t *testing.T) {
	t.Parallel()
	tenantA := createAdminUser(t, "iso-oidc-a")
	tenantB := createAdminUser(t, "iso-oidc-b")
	ctx := context.Background()

	// Create OIDC provider in tenant A
	providerA, err := tenantA.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:   "Tenant A Provider",
		IssuerURL:      util.LoadConfig().OIDCMockInternalURL + "/default",
		ClientID:       "tenant-a-client",
		ClientSecret:   "tenant-a-secret",
		AllowedDomains: []string{"tenanta.com"},
		Enabled:        true,
	})
	require.NoError(t, err)

	t.Run("tenant B cannot see tenant A providers", func(t *testing.T) {
		providers, err := tenantB.Client.ListOIDCProviders(ctx)
		require.NoError(t, err)

		for _, p := range providers.Providers {
			assert.NotEqual(t, providerA.ID, p.ID, "tenant B should not see tenant A providers")
		}
	})

	t.Run("tenant B cannot get tenant A provider by ID", func(t *testing.T) {
		_, err := tenantB.Client.GetOIDCProvider(ctx, sdk.GetOIDCProviderRequest{
			ProviderID: providerA.ID,
		})
		assert.Error(t, err)
	})

	t.Run("tenant B delete of tenant A provider has no effect", func(t *testing.T) {
		// Delete may return error or silently no-op depending on RLS behavior
		_ = tenantB.Client.DeleteOIDCProvider(ctx, sdk.DeleteOIDCProviderRequest{
			ProviderID: providerA.ID,
		})

		// Verify tenant A provider still exists regardless
		provider, err := tenantA.Client.GetOIDCProvider(ctx, sdk.GetOIDCProviderRequest{
			ProviderID: providerA.ID,
		})
		require.NoError(t, err)
		assert.Equal(t, providerA.ID, provider.ID)
	})
}
