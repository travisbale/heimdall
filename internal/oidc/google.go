package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/travisbale/heimdall/internal/auth"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// GoogleProvider implements Google OIDC for individual OAuth login (not SSO)
type GoogleProvider struct {
	config   *oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

func NewGoogleProvider(ctx context.Context, clientID, clientSecret, redirectURI string) (*GoogleProvider, error) {
	// Performs OIDC discovery to fetch Google's endpoints and public keys
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(), // Auto-discovered from .well-known/openid-configuration
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	return &GoogleProvider{
		config:   config,
		provider: provider,
		verifier: verifier,
	}, nil
}

// GetAuthorizationURL generates Google OAuth URL with PKCE and consent prompt
func (g *GoogleProvider) GetAuthorizationURL(state, codeVerifier, redirectURI string) (string, error) {
	if redirectURI != "" {
		g.config.RedirectURL = redirectURI
	}

	codeChallenge := generateCodeChallenge(codeVerifier)

	authURL := g.config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("access_type", "offline"), // Request refresh token
		oauth2.SetAuthURLParam("prompt", "consent"),      // Force consent to get refresh token
	)

	return authURL, nil
}

// ExchangeCode exchanges authorization code for tokens with PKCE verification
func (g *GoogleProvider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*auth.OIDCTokenResponse, error) {
	if redirectURI != "" {
		g.config.RedirectURL = redirectURI // Must match redirect_uri from authorization request
	}

	token, err := g.config.Exchange(
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
		TokenType:    token.TokenType,
	}, nil
}

// GetUserInfo retrieves user information from the provider
func (g *GoogleProvider) GetUserInfo(ctx context.Context, accessToken string) (*auth.OIDCUserInfo, error) {
	// Create an OAuth2 token source
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
	})

	// Get user info from Google
	userInfo, err := g.provider.UserInfo(ctx, tokenSource)
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
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Locale        string `json:"locale"`
	}

	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse user info claims: %w", err)
	}

	// Convert to our domain model
	metadata := map[string]any{
		"given_name":  claims.GivenName,
		"family_name": claims.FamilyName,
		"locale":      claims.Locale,
	}

	result := &auth.OIDCUserInfo{
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
func (g *GoogleProvider) ValidateIDToken(ctx context.Context, idToken string) (*auth.OIDCClaims, error) {
	// Verify the ID token signature and claims
	token, err := g.verifier.Verify(ctx, idToken)
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

// generateCodeChallenge creates SHA256 hash of PKCE verifier for S256 challenge method
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
