package oidc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestOAuthCallback(t *testing.T) {
	t.Parallel()
	client := setup.CreateClient(t)
	ctx := context.Background()

	t.Run("complete Google OAuth flow", func(t *testing.T) {
		// Initiate OAuth login
		authResp, err := client.OAuthLogin(ctx, sdk.OIDCLoginRequest{
			ProviderType: sdk.OIDCProviderTypeGoogle,
		})
		require.NoError(t, err)
		require.NotEmpty(t, authResp.AuthorizationURL)

		// Complete the OAuth flow through the mock OIDC server
		tokenResp := FollowOAuthFlow(t, authResp.AuthorizationURL)
		assert.NotEmpty(t, tokenResp.AccessToken)
		assert.Equal(t, "Bearer", tokenResp.TokenType)
		assert.Greater(t, tokenResp.ExpiresIn, 0)
	})
}

func TestIndividualOAuthLogin(t *testing.T) {
	t.Parallel()
	client := setup.CreateClient(t)
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
