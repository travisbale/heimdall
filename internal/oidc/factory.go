package oidc

import (
	"context"

	"github.com/travisbale/heimdall/internal/auth"
)

// ProviderFactory creates OIDC provider instances
type ProviderFactory struct{}

// NewProviderFactory creates a new provider factory
func NewProviderFactory() *ProviderFactory {
	return &ProviderFactory{}
}

// NewProvider creates a new OIDC provider instance
func (f *ProviderFactory) NewProvider(ctx context.Context, issuerURL, clientID, clientSecret string, scopes []string) (auth.OIDCProvider, error) {
	return NewGenericProvider(ctx, issuerURL, clientID, clientSecret, scopes)
}
