package app

import (
	"context"
	"fmt"

	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/oidc"
	"github.com/travisbale/heimdall/sdk"
)

// initializeSystemProviders creates OAuth/OIDC provider instances for individual logins
// System-wide providers enable "Login with Google/GitHub" before user authentication
// Tenant-specific providers (stored in DB) are used for enterprise SSO
func initializeSystemProviders(ctx context.Context, config *Config) (map[sdk.OIDCProviderType]auth.OIDCProvider, error) {
	systemProviders := make(map[sdk.OIDCProviderType]auth.OIDCProvider)

	// OAuth callback redirect URI (same for all providers)
	redirectURI := config.PublicURL + "/v1/oauth/callback"

	// Configure Google OAuth provider if credentials are provided
	if config.GoogleClientID != "" && config.GoogleClientSecret != "" {
		googleProvider, err := oidc.NewGoogleProvider(ctx, &oidc.ProviderConfig{
			ClientID:     config.GoogleClientID,
			ClientSecret: config.GoogleClientSecret,
			RedirectURI:  redirectURI,
			IssuerURL:    config.GoogleIssuerURL,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create Google OAuth provider: %w", err)
		}
		systemProviders[sdk.OIDCProviderTypeGoogle] = googleProvider
	}

	// Configure Microsoft OAuth provider if credentials are provided
	if config.MicrosoftClientID != "" && config.MicrosoftClientSecret != "" {
		microsoftProvider, err := oidc.NewMicrosoftProvider(ctx, &oidc.ProviderConfig{
			ClientID:     config.MicrosoftClientID,
			ClientSecret: config.MicrosoftClientSecret,
			RedirectURI:  redirectURI,
			TenantID:     config.MicrosoftTenantID,
			IssuerURL:    config.MicrosoftIssuerURL,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create Microsoft OAuth provider: %w", err)
		}
		systemProviders[sdk.OIDCProviderTypeMicrosoft] = microsoftProvider
	}

	// Configure GitHub OAuth provider if credentials are provided
	if config.GitHubClientID != "" && config.GitHubClientSecret != "" {
		githubProvider := oidc.NewGitHubProvider(&oidc.ProviderConfig{
			ClientID:     config.GitHubClientID,
			ClientSecret: config.GitHubClientSecret,
			RedirectURI:  redirectURI,
			AuthURL:      config.GitHubAuthURL,
			TokenURL:     config.GitHubTokenURL,
			APIBase:      config.GitHubAPIBase,
		})
		systemProviders[sdk.OIDCProviderTypeGitHub] = githubProvider
	}

	return systemProviders, nil
}
