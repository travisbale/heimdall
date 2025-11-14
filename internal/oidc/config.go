package oidc

// ProviderConfig contains configuration for creating OAuth/OIDC providers
type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string

	// OIDC providers (Google, Microsoft)
	IssuerURL string

	// Microsoft-specific
	TenantID string

	// GitHub-specific (plain OAuth2, not OIDC)
	AuthURL  string
	TokenURL string
	APIBase  string
}
