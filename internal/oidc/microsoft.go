package oidc

import (
	"context"
	"fmt"
	"strings"

	"github.com/travisbale/heimdall/internal/auth"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// MicrosoftProvider implements OIDC authentication for Microsoft (Azure AD)
type MicrosoftProvider struct {
	config   *oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// NewMicrosoftProvider creates a new Microsoft OIDC provider
func NewMicrosoftProvider(ctx context.Context, cfg *ProviderConfig) (*MicrosoftProvider, error) {
	// Use OIDC discovery
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Use the microsoft package endpoint which handles tenant properly (unless overridden)
	var endpoint oauth2.Endpoint
	if cfg.IssuerURL == fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", cfg.TenantID) {
		endpoint = microsoft.AzureADEndpoint(cfg.TenantID)
	} else {
		// Custom endpoint for testing - use discovered endpoints
		endpoint = provider.Endpoint()
	}

	config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
		Endpoint:     endpoint,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	return &MicrosoftProvider{
		config:   config,
		provider: provider,
		verifier: verifier,
	}, nil
}

// GetAuthorizationURL generates the OAuth authorization URL with PKCE
func (m *MicrosoftProvider) GetAuthorizationURL(state, codeVerifier, redirectURI string) (string, error) {
	// Update redirect URI if provided
	if redirectURI != "" {
		m.config.RedirectURL = redirectURI
	}

	// Generate PKCE code challenge
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Build authorization URL with PKCE
	authURL := m.config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("response_type", "code"),
		oauth2.SetAuthURLParam("response_mode", "query"),
	)

	return authURL, nil
}

// ExchangeCode exchanges an authorization code for tokens
func (m *MicrosoftProvider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*auth.OIDCTokenResponse, error) {
	// Update redirect URI for token exchange (must match authorization)
	if redirectURI != "" {
		m.config.RedirectURL = redirectURI
	}

	// Exchange code for tokens with PKCE verifier
	token, err := m.config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Extract ID token from the response
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	return &auth.OIDCTokenResponse{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    int(token.Expiry.Sub(token.Expiry.Add(-token.Expiry.Sub(token.Expiry))) / 1e9),
	}, nil
}

// GetUserInfo retrieves user information from the provider
func (m *MicrosoftProvider) GetUserInfo(ctx context.Context, accessToken string) (*auth.OIDCUserInfo, error) {
	// Create an OAuth2 token source
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
	})

	// Get user info from Microsoft
	userInfo, err := m.provider.UserInfo(ctx, tokenSource)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Parse the claims
	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}

	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse user info claims: %w", err)
	}

	result := &auth.OIDCUserInfo{
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
func (m *MicrosoftProvider) ValidateIDToken(ctx context.Context, idToken string) (*auth.OIDCClaims, error) {
	// Verify the ID token signature and claims
	token, err := m.verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Parse the standard claims
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}

	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	return &auth.OIDCClaims{
		Sub:           token.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Picture:       claims.Picture,
		Issuer:        token.Issuer,
		Audience:      strings.Join(token.Audience, ","),
		ExpiresAt:     token.Expiry,
		IssuedAt:      token.IssuedAt,
	}, nil
}
