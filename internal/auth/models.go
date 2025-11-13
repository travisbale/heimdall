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

// OIDCRegistrationMethod tracks whether client credentials were entered manually or via RFC 7591
type OIDCRegistrationMethod string

const (
	OIDCRegistrationMethodManual  OIDCRegistrationMethod = "manual"  // Admin manually entered client ID/secret
	OIDCRegistrationMethodDynamic OIDCRegistrationMethod = "dynamic" // Dynamically registered via RFC 7591
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

// OIDCProviderConfig represents tenant-specific OIDC provider for corporate SSO
type OIDCProviderConfig struct {
	ID       uuid.UUID
	TenantID uuid.UUID

	ProviderName string // User-defined display name (e.g., "Azure AD - Production")
	IssuerURL    string // OIDC discovery URL (e.g., https://login.microsoftonline.com/tenant-id)

	ClientID     string
	ClientSecret string

	Scopes  []string
	Enabled bool

	// Domain-based SSO routing
	AllowedDomains           []string // Email domains that trigger this provider (e.g., ['acmecorp.com'])
	AutoCreateUsers          bool     // Auto-provision users on first SSO login
	RequireEmailVerification bool     // Require provider to verify email

	// RFC 7591 dynamic registration metadata (empty for manual registration)
	RegistrationAccessToken string
	RegistrationClientURI   string
	ClientIDIssuedAt        *time.Time
	ClientSecretExpiresAt   *time.Time

	RegistrationMethod OIDCRegistrationMethod

	CreatedAt time.Time
	UpdatedAt time.Time
}

// UpdateOIDCProviderParams supports partial updates using optional pointer fields
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

// OIDCLink tracks SSO users by provider's immutable sub claim (not email)
type OIDCLink struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	OIDCProviderID   uuid.UUID
	ProviderUserID   string         // Provider's immutable 'sub' claim (allows email reassignment)
	ProviderEmail    string         // Email at time of link (may change at provider)
	ProviderMetadata map[string]any // Additional claims (name, picture, etc.)
	LinkedAt         time.Time
	LastUsedAt       *time.Time
}

// OIDCSession tracks OAuth flow state for CSRF protection and PKCE
type OIDCSession struct {
	ID             uuid.UUID
	State          string                // Random state for CSRF protection
	CodeVerifier   string                // PKCE code verifier (hashed in authorization URL)
	OIDCProviderID *uuid.UUID            // Tenant-specific provider for SSO
	ProviderType   *sdk.OIDCProviderType // System-wide provider for individual OAuth
	RedirectURI    string
	TenantID       *uuid.UUID
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// OIDCDiscoveryMetadata from provider's .well-known/openid-configuration endpoint
type OIDCDiscoveryMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	RegistrationEndpoint  string   `json:"registration_endpoint"` // RFC 7591 dynamic registration
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
}

// OIDCRegistration represents RFC 7591 dynamic client registration response
type OIDCRegistration struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        *int64   `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`  // 0 = never expires
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"` // For RFC 7592 management
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`   // Update/delete endpoint
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

// OIDCUserInfo from provider's userinfo endpoint (standard + custom claims)
type OIDCUserInfo struct {
	Sub           string // Provider's unique user ID (immutable)
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Metadata      map[string]any // Provider-specific claims
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
