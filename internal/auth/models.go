package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// UserStatus represents the status of a user
type UserStatus string

const (
	UserStatusUnverified UserStatus = "unverified"
	UserStatusActive     UserStatus = "active"
	UserStatusSuspended  UserStatus = "suspended"
	UserStatusInactive   UserStatus = "inactive"
)

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusInactive  TenantStatus = "inactive"
)

// OIDCRegistrationMethod represents how an OIDC provider was registered
type OIDCRegistrationMethod string

const (
	OIDCRegistrationMethodManual  OIDCRegistrationMethod = "manual"
	OIDCRegistrationMethodDynamic OIDCRegistrationMethod = "dynamic"
)

// User represents a user in the system
type User struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	Email        string
	PasswordHash string
	Status       UserStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  *time.Time
}

// Tenant represents a tenant in the system
type Tenant struct {
	ID        uuid.UUID
	Name      string
	Status    TenantStatus
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Token represents a temporary token (verification, password reset, etc.)
type Token struct {
	UserID    uuid.UUID
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// OIDCProviderConfig represents an OIDC provider configuration
type OIDCProviderConfig struct {
	ID       uuid.UUID
	TenantID uuid.UUID

	// User-defined name for display (e.g., "Azure AD - Production", "Google Workspace")
	ProviderName string

	// OIDC issuer URL for discovery (e.g., https://accounts.google.com)
	IssuerURL string

	// OAuth client credentials (populated by dynamic registration)
	ClientID     string
	ClientSecret string

	// Configuration
	Scopes  []string
	Enabled bool

	// Enterprise SSO configuration
	AllowedDomains           []string // Email domains allowed (e.g., ['acmecorp.com'])
	AutoCreateUsers          bool     // Automatically create users on first SSO login
	RequireEmailVerification bool     // Require email verification for auto-created users

	// Dynamic Client Registration (RFC 7591) - optional fields
	RegistrationAccessToken string     // Token to manage the dynamic registration (empty = not set)
	RegistrationClientURI   string     // Endpoint to update/delete the registration (empty = not set)
	ClientIDIssuedAt        *time.Time // When credentials were issued
	ClientSecretExpiresAt   *time.Time // When secret expires (provider-dependent)

	// Registration method tracking
	RegistrationMethod OIDCRegistrationMethod // How this provider was registered (manual or dynamic)

	// Metadata
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UpdateOIDCProviderParams represents the parameters for updating an OIDC provider
// All fields are optional pointers to support partial updates
type UpdateOIDCProviderParams struct {
	ID                       uuid.UUID
	ProviderName             *string
	ClientSecret             *string
	Scopes                   []string
	Enabled                  *bool
	AllowedDomains           []string
	AutoCreateUsers          *bool
	RequireEmailVerification *bool
}

// OIDCLink represents a link between a user and an OIDC provider
type OIDCLink struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	OIDCProviderID   uuid.UUID // Reference to oidc_providers table
	ProviderUserID   string    // Provider's unique identifier (e.g., Google's 'sub' claim)
	ProviderEmail    string
	ProviderMetadata map[string]any // Store additional provider data (name, picture, etc.)
	LinkedAt         time.Time
	LastUsedAt       *time.Time
}

// OIDCSession represents an OIDC flow session
type OIDCSession struct {
	ID             uuid.UUID
	State          string                // CSRF protection
	CodeVerifier   string                // PKCE support
	OIDCProviderID *uuid.UUID            // For corporate SSO (references oidc_providers table)
	ProviderType   *sdk.OIDCProviderType // For system-wide providers (individual OAuth)
	RedirectURI    string
	TenantID       *uuid.UUID
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// OIDCDiscoveryMetadata represents the OIDC discovery document
// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type OIDCDiscoveryMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	RegistrationEndpoint  string   `json:"registration_endpoint"` // RFC 7591
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
}

// OIDCRegistration represents an RFC 7591 dynamically registered client
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1
type OIDCRegistration struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        *int64   `json:"client_id_issued_at,omitempty"`       // Unix timestamp
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`  // Unix timestamp, 0 = never expires
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"` // Token to manage registration
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`   // Endpoint to manage this client
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
}

// OIDCProvider defines the interface for OIDC provider implementations
type OIDCProvider interface {
	// GetAuthorizationURL generates the OAuth authorization URL with PKCE
	GetAuthorizationURL(state, codeVerifier, redirectURI string, scopes []string) (string, error)

	// ExchangeCode exchanges an authorization code for tokens
	ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*OIDCTokenResponse, error)

	// GetUserInfo retrieves user information from the provider
	GetUserInfo(ctx context.Context, accessToken string) (*OIDCUserInfo, error)

	// ValidateIDToken validates and parses an ID token
	ValidateIDToken(ctx context.Context, idToken string) (*OIDCClaims, error)
}

// OIDCTokenResponse represents the response from an OAuth token exchange
type OIDCTokenResponse struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresIn    int
	TokenType    string
}

// OIDCUserInfo represents user information from an OIDC provider
type OIDCUserInfo struct {
	Sub           string // Provider's unique user ID
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Metadata      map[string]any // Additional provider-specific fields
}

// OIDCClaims represents the claims from an ID token
type OIDCClaims struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Issuer        string
	Audience      string
	ExpiresAt     time.Time
	IssuedAt      time.Time
}
