package oidc

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/travisbale/heimdall/internal/auth"
	"golang.org/x/oauth2"
)

// GenericProvider implements any OIDC-compliant provider using coreos/go-oidc library
type GenericProvider struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

// NewGenericProvider creates OIDC provider with automatic discovery and configuration
func NewGenericProvider(ctx context.Context, issuerURL, clientID, clientSecret string, scopes []string) (*GenericProvider, error) {
	// Performs OIDC discovery to fetch endpoints (coreos/go-oidc handles caching)
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider: %w", err)
	}

	return &GenericProvider{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: clientID,
		}),
		oauth2Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
	}, nil
}

// GetAuthorizationURL generates OAuth authorization URL with PKCE for secure public clients
func (p *GenericProvider) GetAuthorizationURL(state, codeVerifier, redirectURI string) (string, error) {
	config := p.oauth2Config
	config.RedirectURL = redirectURI

	// PKCE prevents authorization code interception attacks
	codeChallenge := generateCodeChallenge(codeVerifier)

	authURL := config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	return authURL, nil
}

// ExchangeCode exchanges authorization code for access and ID tokens using PKCE
func (p *GenericProvider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*auth.OIDCTokenResponse, error) {
	p.oauth2Config.RedirectURL = redirectURI

	// PKCE verifier must match the challenge sent in authorization request
	authCodeOpt := oauth2.SetAuthURLParam("code_verifier", codeVerifier)
	token, err := p.oauth2Config.Exchange(ctx, code, authCodeOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// ID token contains user identity claims signed by provider
	var idToken string
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

// GetUserInfo retrieves user profile from provider's userinfo endpoint
func (p *GenericProvider) GetUserInfo(ctx context.Context, accessToken string) (*auth.OIDCUserInfo, error) {
	token := &oauth2.Token{
		AccessToken: accessToken,
	}

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

	// Capture all claims for provider-specific attributes
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

// ValidateIDToken validates ID token signature and expiration, returns claims
func (p *GenericProvider) ValidateIDToken(ctx context.Context, rawIDToken string) (*auth.OIDCClaims, error) {
	// Verifies signature using provider's public keys (from JWKS endpoint)
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
