package oidc

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/travisbale/heimdall/internal/auth"
	"golang.org/x/oauth2"
)

// GenericProvider is a generic OIDC provider implementation using coreos/go-oidc
// It works with any OIDC-compliant provider (Okta, Auth0, Keycloak, etc.)
type GenericProvider struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

// NewGenericProvider creates a new generic OIDC provider
// It performs OIDC discovery to get the provider's configuration
func NewGenericProvider(ctx context.Context, issuerURL, clientID, clientSecret string, scopes []string) (*GenericProvider, error) {
	// Perform OIDC discovery (coreos/go-oidc caches this)
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider: %w", err)
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	// Get OAuth2 endpoints from discovery
	endpoint := provider.Endpoint()

	// Create OAuth2 config (redirect URI set dynamically in GetAuthorizationURL)
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     endpoint,
		Scopes:       scopes,
	}

	return &GenericProvider{
		provider:     provider,
		verifier:     verifier,
		oauth2Config: oauth2Config,
	}, nil
}

// GetAuthorizationURL generates the OAuth authorization URL with PKCE
func (p *GenericProvider) GetAuthorizationURL(state, codeVerifier, redirectURI string, scopes []string) (string, error) {
	// Update redirect URI if different from config
	config := p.oauth2Config
	if redirectURI != "" {
		config.RedirectURL = redirectURI
	}
	if len(scopes) > 0 {
		config.Scopes = scopes
	}

	// Generate PKCE code challenge from verifier
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Build authorization URL with PKCE
	authURL := config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	return authURL, nil
}

// ExchangeCode exchanges an authorization code for tokens
func (p *GenericProvider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*auth.OIDCTokenResponse, error) {
	// Update redirect URI if different from config
	config := p.oauth2Config
	if redirectURI != "" {
		config.RedirectURL = redirectURI
	}

	// Exchange code for token (with PKCE verifier)
	token, err := config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Extract ID token if present
	idToken := ""
	if rawIDToken, ok := token.Extra("id_token").(string); ok {
		idToken = rawIDToken
	}

	return &auth.OIDCTokenResponse{
		AccessToken:  token.AccessToken,
		IDToken:      idToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    int(token.Expiry.Sub(token.Expiry).Seconds()),
		TokenType:    token.TokenType,
	}, nil
}

// GetUserInfo retrieves user information from the provider
func (p *GenericProvider) GetUserInfo(ctx context.Context, accessToken string) (*auth.OIDCUserInfo, error) {
	// Create an OAuth2 token for the userinfo request
	token := &oauth2.Token{
		AccessToken: accessToken,
	}

	// Fetch userinfo from the provider's userinfo endpoint
	userInfo, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Parse standard claims
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

	// Parse all claims into metadata
	var allClaims map[string]any
	if err := userInfo.Claims(&allClaims); err != nil {
		return nil, fmt.Errorf("failed to parse user info metadata: %w", err)
	}

	return &auth.OIDCUserInfo{
		Sub:           claims.Sub,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Picture:       claims.Picture,
		Metadata:      allClaims,
	}, nil
}

// ValidateIDToken validates and parses an ID token
func (p *GenericProvider) ValidateIDToken(ctx context.Context, rawIDToken string) (*auth.OIDCClaims, error) {
	// Verify the ID token
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Parse standard claims
	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	return &auth.OIDCClaims{
		Sub:           claims.Sub,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Picture:       claims.Picture,
		Issuer:        idToken.Issuer,
		Audience:      idToken.Subject,
		ExpiresAt:     idToken.Expiry,
		IssuedAt:      idToken.IssuedAt,
	}, nil
}
