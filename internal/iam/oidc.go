package iam

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// defaultOIDCScopes returns a fresh copy of standard OIDC scopes
func defaultOIDCScopes() []string {
	return []string{"openid", "email", "profile"}
}

// oauthCallbackURL constructs the OAuth callback URL from a base public URL
func oauthCallbackURL(publicURL string) string {
	return publicURL + sdk.RouteV1OAuthCallback
}

// oidcSessionExpiration is the timeout for OIDC flow sessions (CSRF/PKCE state)
const oidcSessionExpiration = 15 * time.Minute

// oidcProviderDB defines the interface for OIDC provider database operations
type oidcProviderDB interface {
	CreateOIDCProvider(ctx context.Context, provider *OIDCProviderConfig) (*OIDCProviderConfig, error)
	GetOIDCProviderByID(ctx context.Context, id uuid.UUID) (*OIDCProviderConfig, error)
	GetOIDCProvidersByDomain(ctx context.Context, domain string) ([]*OIDCProviderConfig, error)
	ListOIDCProviders(ctx context.Context) ([]*OIDCProviderConfig, error)
	UpdateOIDCProvider(ctx context.Context, params *UpdateOIDCProviderParams) (*OIDCProviderConfig, error)
	DeleteOIDCProviderByID(ctx context.Context, id uuid.UUID) error
}

// oidcLinkDB defines the interface for OIDC link database operations
type oidcLinkDB interface {
	CreateOIDCLink(ctx context.Context, link *OIDCLink) (*OIDCLink, error)
	GetOIDCLinkByProvider(ctx context.Context, providerID uuid.UUID, providerUserID string) (*OIDCLink, error)
	GetOIDCLinkByUser(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) (*OIDCLink, error)
	ListOIDCLinksByUser(ctx context.Context, userID uuid.UUID) ([]*OIDCLink, error)
	UpdateOIDCLinkLastUsed(ctx context.Context, id uuid.UUID) error
	DeleteOIDCLink(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) error
}

// oidcSessionDB defines the interface for OIDC session database operations
type oidcSessionDB interface {
	CreateOIDCSession(ctx context.Context, session *OIDCSession) (*OIDCSession, error)
	GetOIDCSessionByState(ctx context.Context, state string) (*OIDCSession, error)
	DeleteOIDCSession(ctx context.Context, id uuid.UUID) error
	DeleteExpiredOIDCSessions(ctx context.Context) error
}

// oidcRegistrationClient defines the interface for OIDC discovery and dynamic registration
type oidcRegistrationClient interface {
	Discover(ctx context.Context, issuerURL string) (*OIDCDiscoveryMetadata, error)
	Register(ctx context.Context, registrationEndpoint, callbackURL, clientName, accessToken string, scopes []string) (*OIDCRegistration, error)
	Unregister(ctx context.Context, registrationClientURI, registrationAccessToken string) error
}

// oidcProviderFactory creates OIDC provider instances from configuration
type oidcProviderFactory interface {
	NewProvider(ctx context.Context, issuerURL, clientID, clientSecret string, scopes []string) (OIDCProvider, error)
}

// OIDCProvider defines the interface for OIDC provider implementations
type OIDCProvider interface {
	// GetAuthorizationURL generates the OAuth authorization URL with PKCE
	GetAuthorizationURL(state, codeVerifier, redirectURI string) (string, error)

	// ExchangeCode exchanges an authorization code for tokens
	ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*OIDCTokenResponse, error)

	// GetUserInfo retrieves user information from the provider
	GetUserInfo(ctx context.Context, accessToken string) (*OIDCUserInfo, error)

	// ValidateIDToken validates and parses an ID token
	ValidateIDToken(ctx context.Context, idToken string) (*OIDCClaims, error)
}
