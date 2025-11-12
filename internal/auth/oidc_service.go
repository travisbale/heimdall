package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// defaultOIDCScopes are the standard OIDC scopes requested by default
var defaultOIDCScopes = []string{"openid", "email", "profile"}

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

// OIDCServiceConfig holds the dependencies for creating an OIDCService
type OIDCServiceConfig struct {
	OIDCProviderDB     oidcProviderDB
	OIDCLinkDB         oidcLinkDB
	OIDCSessionDB      oidcSessionDB
	UserDB             userDB
	SystemProviders    map[sdk.OIDCProviderType]OIDCProvider // System-wide providers for public login (from env vars)
	RegistrationClient oidcRegistrationClient                // Client for OIDC discovery and dynamic registration
	ProviderFactory    oidcProviderFactory                   // Factory for creating provider instances
	PublicURL          string
	Logger             logger
}

// OIDCService handles OIDC business logic
type OIDCService struct {
	oidcProviderDB     oidcProviderDB
	oidcLinkDB         oidcLinkDB
	oidcSessionDB      oidcSessionDB
	userDB             userDB
	systemProviders    map[sdk.OIDCProviderType]OIDCProvider // System-wide providers for public login
	registrationClient oidcRegistrationClient
	providerFactory    oidcProviderFactory
	publicURL          string
	logger             logger
}

// NewOIDCService creates a new OIDC service
func NewOIDCService(config *OIDCServiceConfig) *OIDCService {
	return &OIDCService{
		oidcProviderDB:     config.OIDCProviderDB,
		oidcLinkDB:         config.OIDCLinkDB,
		oidcSessionDB:      config.OIDCSessionDB,
		userDB:             config.UserDB,
		systemProviders:    config.SystemProviders,
		registrationClient: config.RegistrationClient,
		providerFactory:    config.ProviderFactory,
		publicURL:          config.PublicURL,
		logger:             config.Logger,
	}
}

// getCallbackURL returns the full OAuth callback URL
func (s *OIDCService) getCallbackURL() string {
	return s.publicURL + sdk.RouteV1OAuthCallback
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(numBytes int) (string, error) {
	bytes := make([]byte, numBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// extractEmailDomain extracts the domain from an email address
// Assumes the email is already validated (contains @ symbol)
func extractEmailDomain(email string) string {
	// Find the @ symbol (searching from the end for efficiency)
	atIndex := -1
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			atIndex = i
			break
		}
	}

	return email[atIndex+1:]
}
