package oidc

import (
	"context"

	"github.com/travisbale/heimdall/internal/auth"
)

// ProviderFactory creates OIDC provider instances for tenant-specific SSO configurations
type ProviderFactory struct{}

func NewProviderFactory() *ProviderFactory {
	return &ProviderFactory{}
}

// NewProvider creates a new OIDC provider instance with discovery and validation
func (f *ProviderFactory) NewProvider(ctx context.Context, issuerURL, clientID, clientSecret string, scopes []string) (auth.OIDCProvider, error) {
	return NewGenericProvider(ctx, issuerURL, clientID, clientSecret, scopes)
}
