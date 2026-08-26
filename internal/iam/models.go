package iam

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

type UserStatus string

const (
	UserStatusUnverified UserStatus = "unverified"
	UserStatusActive     UserStatus = "active"
	UserStatusSuspended  UserStatus = "suspended"
	UserStatusInactive   UserStatus = "inactive"
)

type Tenant struct {
	ID uuid.UUID
}

type User struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	Email        string
	PasswordHash string
	FirstName    string
	LastName     string
	Status       UserStatus
	LastLoginAt  *time.Time
}

// UpdateUserParams supports partial updates using optional pointer fields
type UpdateUserParams struct {
	ID           uuid.UUID
	PasswordHash *string
	Status       *UserStatus
}

// UserToken is a short-lived token emailed to a user: email verification, or a password reset.
type UserToken struct {
	UserID    uuid.UUID
	Token     string
	ExpiresAt time.Time
}

// OIDCProviderConfig is a tenant's own SSO provider, as opposed to the system-wide ones
// behind individual OAuth login.
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

	RegistrationMethod sdk.OIDCRegistrationMethod
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

// OIDCRegistration is what a provider returns from RFC 7591 dynamic client registration.
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

// OIDCTokenResponse is what an OAuth token exchange returns.
type OIDCTokenResponse struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresIn    int
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

// Validate checks that required claims are present
func (u *OIDCUserInfo) Validate() error {
	if u.Sub == "" {
		return fmt.Errorf("provider did not return required sub claim")
	}
	if u.Email == "" {
		return fmt.Errorf("provider did not return required email claim")
	}
	return nil
}

// OIDCClaims is the claim set carried by an ID token.
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

// Permission is a permission name. They are system-wide, unlike the roles that grant them.
type Permission struct {
	ID          uuid.UUID
	Name        string // e.g., "employee:create"
	Description string
}

// Role is a tenant's own grouping of permissions.
type Role struct {
	ID          uuid.UUID
	Name        string
	Description string
	MFARequired bool
}

// UpdateRoleParams supports partial updates using optional pointer fields
type UpdateRoleParams struct {
	ID          uuid.UUID
	Name        *string
	Description *string
	MFARequired *bool
}

// EffectivePermission is a permission a user holds, whether by role or directly.
type EffectivePermission struct {
	Permission *Permission
	Effect     sdk.PermissionEffect
}

// DirectPermission is one entry in a replacement set of a user's direct permissions.
type DirectPermission struct {
	PermissionID uuid.UUID
	Effect       sdk.PermissionEffect
}

type MFASettings struct {
	UserID         uuid.UUID
	TOTPSecret     string
	LastUsedWindow *int64
	VerifiedAt     *time.Time
	LastUsedAt     *time.Time
}

// MFABackupCode is a recovery code, usable once.
type MFABackupCode struct {
	ID       uuid.UUID
	UserID   uuid.UUID
	CodeHash string
	Used     bool
	UsedAt   *time.Time
}

// MFAEnrollment contains TOTP enrollment data
type MFAEnrollment struct {
	Secret      string   // Base32 encoded secret
	QRCode      string   // data:image/png;base64,...
	BackupCodes []string // Plain text (shown once)
}

// MFAStatus is a user's MFA state and how many backup codes they have left.
type MFAStatus struct {
	VerifiedAt           *time.Time
	BackupCodesRemaining int
}

// RefreshToken is a stored session: the row a refresh token is checked and revoked against.
type RefreshToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	FamilyID   uuid.UUID // Token family for rotation tracking
	UserAgent  string
	IPAddress  string
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
}

// TrustedDevice is a device allowed to skip MFA until its trust expires.
type TrustedDevice struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	UserAgent  string
	IPAddress  string
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
}
