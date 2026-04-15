package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	util "github.com/travisbale/heimdall/test/_util"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestListSupportedOIDCProviderTypes(t *testing.T) {
	t.Parallel()
	client := setup.CreateClient(t)
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

func TestOIDCMetadataDiscovery(t *testing.T) {
	t.Parallel()

	config := util.LoadConfig()

	t.Run("mock OIDC server returns valid discovery document", func(t *testing.T) {
		resp, err := http.Get(config.OIDCMockURL + "/default/.well-known/openid-configuration")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var metadata map[string]any
		err = json.NewDecoder(resp.Body).Decode(&metadata)
		require.NoError(t, err)

		assert.NotEmpty(t, metadata["issuer"])
		assert.NotEmpty(t, metadata["authorization_endpoint"])
		assert.NotEmpty(t, metadata["token_endpoint"])
	})
}
