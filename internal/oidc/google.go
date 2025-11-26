package oidc

import (
	"context"

	"github.com/travisbale/heimdall/internal/iam"

	"golang.org/x/oauth2"
)

// GoogleProvider implements Google OIDC for individual OAuth login (not SSO)
type GoogleProvider struct {
	*baseOIDCProvider
	issuerURL string // Store issuer URL to distinguish production vs test
}

func NewGoogleProvider(ctx context.Context, cfg *ProviderConfig) (*GoogleProvider, error) {
	base, err := newBaseOIDCProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return &GoogleProvider{
		baseOIDCProvider: base,
		issuerURL:        cfg.IssuerURL,
	}, nil
}

// GetAuthorizationURL generates Google OAuth URL with PKCE and consent prompt
func (g *GoogleProvider) GetAuthorizationURL(state, codeVerifier, redirectURI string) (string, error) {
	var extraParams []oauth2.AuthCodeOption

	// Only add Google-specific params for production Google endpoint
	// Mock OAuth servers don't support prompt=consent and it prevents automatic redirects
	if g.issuerURL == "https://accounts.google.com" {
		extraParams = []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("access_type", "offline"), // Request refresh token
			oauth2.SetAuthURLParam("prompt", "consent"),      // Force consent to get refresh token
		}
	}

	return g.baseOIDCProvider.getAuthorizationURL(state, codeVerifier, redirectURI, extraParams...)
}

// ExchangeCode exchanges authorization code for tokens with PKCE verification
func (g *GoogleProvider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*iam.OIDCTokenResponse, error) {
	return g.baseOIDCProvider.exchangeCode(ctx, code, codeVerifier, redirectURI)
}

// GetUserInfo retrieves user information from the provider
func (g *GoogleProvider) GetUserInfo(ctx context.Context, accessToken string) (*iam.OIDCUserInfo, error) {
	userInfo, err := g.baseOIDCProvider.getUserInfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Locale        string `json:"locale"`
	}

	if err := userInfo.Claims(&claims); err != nil {
		return nil, err
	}

	metadata := map[string]any{
		"given_name":  claims.GivenName,
		"family_name": claims.FamilyName,
		"locale":      claims.Locale,
	}

	result := &iam.OIDCUserInfo{
		Sub:           claims.Sub,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Picture:       claims.Picture,
		Metadata:      metadata,
	}

	if err := result.Validate(); err != nil {
		return nil, err
	}

	return result, nil
}

// ValidateIDToken validates and parses an ID token
func (g *GoogleProvider) ValidateIDToken(ctx context.Context, idToken string) (*iam.OIDCClaims, error) {
	return g.baseOIDCProvider.validateIDToken(ctx, idToken)
}
