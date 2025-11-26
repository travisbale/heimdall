package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/travisbale/heimdall/internal/iam"
	"golang.org/x/oauth2"
)

// baseOIDCProvider contains common OIDC functionality shared by Google, Microsoft, and Okta.
// Providers embed this struct and can override methods for provider-specific behavior.
type baseOIDCProvider struct {
	config   *oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// newBaseOIDCProvider performs OIDC discovery and creates the base provider components
func newBaseOIDCProvider(ctx context.Context, cfg *ProviderConfig) (*baseOIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	return &baseOIDCProvider{
		config:   config,
		provider: provider,
		verifier: verifier,
	}, nil
}

// getAuthorizationURL generates OAuth authorization URL with PKCE
func (b *baseOIDCProvider) getAuthorizationURL(state, codeVerifier, redirectURI string, extraParams ...oauth2.AuthCodeOption) (string, error) {
	if redirectURI != "" {
		b.config.RedirectURL = redirectURI
	}

	codeChallenge := generateCodeChallenge(codeVerifier)

	params := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	params = append(params, extraParams...)

	return b.config.AuthCodeURL(state, params...), nil
}

// exchangeCode exchanges authorization code for tokens with PKCE verification
func (b *baseOIDCProvider) exchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*iam.OIDCTokenResponse, error) {
	if redirectURI != "" {
		b.config.RedirectURL = redirectURI
	}

	token, err := b.config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	return &iam.OIDCTokenResponse{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		ExpiresIn:    int(token.Expiry.Sub(token.Expiry.Add(-token.Expiry.Sub(token.Expiry))) / 1e9),
	}, nil
}

// getUserInfo retrieves user information from the provider's userinfo endpoint
func (b *baseOIDCProvider) getUserInfo(ctx context.Context, accessToken string) (*oidc.UserInfo, error) {
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
	})

	userInfo, err := b.provider.UserInfo(ctx, tokenSource)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	return userInfo, nil
}

// validateIDToken verifies ID token signature and parses claims
func (b *baseOIDCProvider) validateIDToken(ctx context.Context, idToken string) (*iam.OIDCClaims, error) {
	token, err := b.verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}

	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	return &iam.OIDCClaims{
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
