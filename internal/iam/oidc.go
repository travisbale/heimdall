package iam

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// defaultOIDCScopes returns a fresh copy of standard OIDC scopes
func defaultOIDCScopes() []string {
	return []string{"openid", "email", "profile"}
}

// OAuthCallbackURL constructs the OAuth callback URL from frontend base URL
func OAuthCallbackURL(publicURL string) string {
	return publicURL + "/oauth/callback"
}

// oidcSessionExpiration is the timeout for OIDC flow sessions (CSRF/PKCE state)
const oidcSessionExpiration = 15 * time.Minute

type oidcProviderDB interface {
	CreateOIDCProvider(ctx context.Context, provider *OIDCProviderConfig) (*OIDCProviderConfig, error)
	GetOIDCProviderByID(ctx context.Context, id uuid.UUID) (*OIDCProviderConfig, error)
	GetOIDCProvidersByDomain(ctx context.Context, domain string) ([]*OIDCProviderConfig, error)
	ListOIDCProviders(ctx context.Context) ([]*OIDCProviderConfig, error)
	UpdateOIDCProvider(ctx context.Context, params *UpdateOIDCProviderParams) (*OIDCProviderConfig, error)
	DeleteOIDCProviderByID(ctx context.Context, id uuid.UUID) error
}

type oidcLinkDB interface {
	CreateOIDCLink(ctx context.Context, link *OIDCLink) (*OIDCLink, error)
	GetOIDCLinkByProvider(ctx context.Context, providerID uuid.UUID, providerUserID string) (*OIDCLink, error)
	GetOIDCLinkByUser(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) (*OIDCLink, error)
	ListOIDCLinksByUser(ctx context.Context, userID uuid.UUID) ([]*OIDCLink, error)
	UpdateOIDCLinkLastUsed(ctx context.Context, id uuid.UUID) error
	DeleteOIDCLink(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) error
}

type oidcSessionDB interface {
	CreateOIDCSession(ctx context.Context, session *OIDCSession) (*OIDCSession, error)
	GetOIDCSessionByState(ctx context.Context, state string) (*OIDCSession, error)
	DeleteOIDCSession(ctx context.Context, id uuid.UUID) error
	DeleteExpiredOIDCSessions(ctx context.Context) error
}

type oidcRegistrationClient interface {
	Discover(ctx context.Context, issuerURL string) (*OIDCDiscoveryMetadata, error)
	Register(ctx context.Context, registrationEndpoint, callbackURL, clientName, accessToken string, scopes []string) (*OIDCRegistration, error)
	Unregister(ctx context.Context, registrationClientURI, registrationAccessToken string) error
}

// oidcProviderFactory creates OIDC provider instances from configuration
type oidcProviderFactory interface {
	NewProvider(ctx context.Context, issuerURL, clientID, clientSecret string, scopes []string) (OIDCProvider, error)
}

type OIDCProvider interface {
	GetAuthorizationURL(state, codeVerifier, redirectURI string) (string, error)
	ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*OIDCTokenResponse, error)
	GetUserInfo(ctx context.Context, accessToken string) (*OIDCUserInfo, error)
	ValidateIDToken(ctx context.Context, idToken string) (*OIDCClaims, error)
}
