package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/travisbale/heimdall/internal/auth"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GitHubProvider implements OAuth authentication for GitHub
// Note: GitHub uses OAuth 2.0 but doesn't fully support OIDC (no ID tokens)
type GitHubProvider struct {
	config *oauth2.Config
}

// NewGitHubProvider creates a new GitHub OAuth provider
func NewGitHubProvider(clientID, clientSecret, redirectURI string) *GitHubProvider {
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     github.Endpoint,
		Scopes:       []string{"user:email", "read:user"},
	}

	return &GitHubProvider{
		config: config,
	}
}

// GetAuthorizationURL generates the OAuth authorization URL with PKCE
func (g *GitHubProvider) GetAuthorizationURL(state, codeVerifier, redirectURI string) (string, error) {
	// Update redirect URI if provided
	if redirectURI != "" {
		g.config.RedirectURL = redirectURI
	}

	// Generate PKCE code challenge
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Build authorization URL with PKCE
	// Note: GitHub supports PKCE as of 2023
	authURL := g.config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	return authURL, nil
}

// ExchangeCode exchanges an authorization code for tokens
func (g *GitHubProvider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*auth.OIDCTokenResponse, error) {
	// Update redirect URI for token exchange (must match authorization)
	if redirectURI != "" {
		g.config.RedirectURL = redirectURI
	}

	// Exchange code for tokens with PKCE verifier
	token, err := g.config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	return &auth.OIDCTokenResponse{
		AccessToken:  token.AccessToken,
		IDToken:      "", // GitHub doesn't provide ID tokens
		RefreshToken: token.RefreshToken,
		ExpiresIn:    int(time.Until(token.Expiry).Seconds()),
		TokenType:    token.TokenType,
	}, nil
}

// GetUserInfo retrieves user information from GitHub's API
func (g *GitHubProvider) GetUserInfo(ctx context.Context, accessToken string) (*auth.OIDCUserInfo, error) {
	// Get user profile
	user, err := g.getGitHubUser(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	// Get primary verified email
	email, emailVerified, err := g.getGitHubEmail(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	metadata := map[string]any{
		"login":        user.Login,
		"html_url":     user.HTMLURL,
		"bio":          user.Bio,
		"company":      user.Company,
		"location":     user.Location,
		"public_repos": user.PublicRepos,
		"followers":    user.Followers,
		"created_at":   user.CreatedAt,
	}

	return &auth.OIDCUserInfo{
		Sub:           fmt.Sprintf("%d", user.ID), // GitHub uses numeric IDs
		Email:         email,
		EmailVerified: emailVerified,
		Name:          user.Name,
		Picture:       user.AvatarURL,
		Metadata:      metadata,
	}, nil
}

// ValidateIDToken validates and parses an ID token
// Note: GitHub doesn't support OIDC ID tokens, so this returns an error
func (g *GitHubProvider) ValidateIDToken(ctx context.Context, idToken string) (*auth.OIDCClaims, error) {
	return nil, fmt.Errorf("GitHub does not support OIDC ID tokens")
}

// gitHubUser represents a GitHub user profile
type gitHubUser struct {
	ID          int64     `json:"id"`
	Login       string    `json:"login"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	AvatarURL   string    `json:"avatar_url"`
	HTMLURL     string    `json:"html_url"`
	Bio         string    `json:"bio"`
	Company     string    `json:"company"`
	Location    string    `json:"location"`
	PublicRepos int       `json:"public_repos"`
	Followers   int       `json:"followers"`
	CreatedAt   time.Time `json:"created_at"`
}

// gitHubEmail represents a GitHub email
type gitHubEmail struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}

// getGitHubUser fetches the user profile from GitHub
func (g *GitHubProvider) getGitHubUser(ctx context.Context, accessToken string) (*gitHubUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var user gitHubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user: %w", err)
	}

	return &user, nil
}

// getGitHubEmail fetches the primary verified email from GitHub
func (g *GitHubProvider) getGitHubEmail(ctx context.Context, accessToken string) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("failed to get emails: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var emails []gitHubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false, fmt.Errorf("failed to decode emails: %w", err)
	}

	// Find the primary email
	for _, email := range emails {
		if email.Primary {
			return email.Email, email.Verified, nil
		}
	}

	// If no primary email, return the first one
	if len(emails) > 0 {
		return emails[0].Email, emails[0].Verified, nil
	}

	return "", false, fmt.Errorf("no email found for user")
}
