package oidc

import (
	"context"
	"fmt"

	"github.com/travisbale/heimdall/internal/iam"
)

// OktaProvider implements OIDC authentication for Okta
type OktaProvider struct {
	*baseOIDCProvider
}

// NewOktaProvider creates a new Okta OIDC provider
// domain should be your Okta domain (e.g., "dev-12345.okta.com" or "example.okta.com")
func NewOktaProvider(ctx context.Context, domain, clientID, clientSecret, redirectURI string) (*OktaProvider, error) {
	cfg := &ProviderConfig{
		IssuerURL:    fmt.Sprintf("https://%s", domain),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
	}

	base, err := newBaseOIDCProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return &OktaProvider{
		baseOIDCProvider: base,
	}, nil
}

// GetAuthorizationURL generates the OAuth authorization URL with PKCE
func (o *OktaProvider) GetAuthorizationURL(state, codeVerifier, redirectURI string) (string, error) {
	return o.getAuthorizationURL(state, codeVerifier, redirectURI)
}

// ExchangeCode exchanges an authorization code for tokens
func (o *OktaProvider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*iam.OIDCTokenResponse, error) {
	return o.exchangeCode(ctx, code, codeVerifier, redirectURI)
}

// GetUserInfo retrieves user information from the provider
func (o *OktaProvider) GetUserInfo(ctx context.Context, accessToken string) (*iam.OIDCUserInfo, error) {
	userInfo, err := o.getUserInfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Name              string `json:"name"`
		Picture           string `json:"picture"`
		PreferredUsername string `json:"preferred_username"`
		GivenName         string `json:"given_name"`
		FamilyName        string `json:"family_name"`
		ZoneInfo          string `json:"zoneinfo"`
		Locale            string `json:"locale"`
		UpdatedAt         int64  `json:"updated_at"`
	}

	if err := userInfo.Claims(&claims); err != nil {
		return nil, err
	}

	metadata := map[string]any{
		"preferred_username": claims.PreferredUsername,
		"given_name":         claims.GivenName,
		"family_name":        claims.FamilyName,
		"zoneinfo":           claims.ZoneInfo,
		"locale":             claims.Locale,
		"updated_at":         claims.UpdatedAt,
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
func (o *OktaProvider) ValidateIDToken(ctx context.Context, idToken string) (*iam.OIDCClaims, error) {
	return o.validateIDToken(ctx, idToken)
}
