package oidc

import (
	"context"
	"fmt"

	"github.com/travisbale/heimdall/internal/iam"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// MicrosoftProvider implements OIDC authentication for Microsoft (Azure AD)
type MicrosoftProvider struct {
	*baseOIDCProvider
}

// NewMicrosoftProvider creates a new Microsoft OIDC provider
func NewMicrosoftProvider(ctx context.Context, cfg *ProviderConfig) (*MicrosoftProvider, error) {
	base, err := newBaseOIDCProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Use the microsoft package endpoint which handles tenant properly (unless overridden)
	if cfg.IssuerURL == fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", cfg.TenantID) {
		base.config.Endpoint = microsoft.AzureADEndpoint(cfg.TenantID)
	}

	return &MicrosoftProvider{
		baseOIDCProvider: base,
	}, nil
}

// GetAuthorizationURL generates the OAuth authorization URL with PKCE
func (m *MicrosoftProvider) GetAuthorizationURL(state, codeVerifier, redirectURI string) (string, error) {
	extraParams := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("response_type", "code"),
		oauth2.SetAuthURLParam("response_mode", "query"),
	}

	return m.getAuthorizationURL(state, codeVerifier, redirectURI, extraParams...)
}

// ExchangeCode exchanges an authorization code for tokens
func (m *MicrosoftProvider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*iam.OIDCTokenResponse, error) {
	return m.exchangeCode(ctx, code, codeVerifier, redirectURI)
}

// GetUserInfo retrieves user information from the provider
func (m *MicrosoftProvider) GetUserInfo(ctx context.Context, accessToken string) (*iam.OIDCUserInfo, error) {
	userInfo, err := m.getUserInfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}

	if err := userInfo.Claims(&claims); err != nil {
		return nil, err
	}

	result := &iam.OIDCUserInfo{
		Sub:           claims.Sub,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Picture:       claims.Picture,
		Metadata:      make(map[string]any),
	}

	if err := result.Validate(); err != nil {
		return nil, err
	}

	return result, nil
}

// ValidateIDToken validates and parses an ID token
func (m *MicrosoftProvider) ValidateIDToken(ctx context.Context, idToken string) (*iam.OIDCClaims, error) {
	return m.validateIDToken(ctx, idToken)
}
