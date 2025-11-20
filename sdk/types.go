package sdk

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/crypto/password"
)

// emailRegex is a basic email validation pattern
// Matches standard email format: localpart@domain
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// OIDCProviderType represents an OIDC provider type
type OIDCProviderType string

const (
	OIDCProviderTypeGoogle    OIDCProviderType = "google"
	OIDCProviderTypeMicrosoft OIDCProviderType = "microsoft"
	OIDCProviderTypeGitHub    OIDCProviderType = "github"
	OIDCProviderTypeOkta      OIDCProviderType = "okta"
)

// OIDCRegistrationMethod represents how an OIDC provider was registered
type OIDCRegistrationMethod string

const (
	OIDCRegistrationMethodManual  OIDCRegistrationMethod = "manual"
	OIDCRegistrationMethodDynamic OIDCRegistrationMethod = "dynamic"
)

// PermissionEffect represents the effect of a permission (allow/deny)
type PermissionEffect string

const (
	PermissionAllow PermissionEffect = "allow"
	PermissionDeny  PermissionEffect = "deny"
)

// IsValid checks if the provider type is one of the defined valid types
func (p OIDCProviderType) IsValid() bool {
	switch p {
	case OIDCProviderTypeGoogle, OIDCProviderTypeMicrosoft, OIDCProviderTypeGitHub, OIDCProviderTypeOkta:
		return true
	default:
		return false
	}
}

// String returns the string representation of the provider type
func (p OIDCProviderType) String() string {
	return string(p)
}

// DisplayName returns a human-readable name for the provider
func (p OIDCProviderType) DisplayName() string {
	switch p {
	case OIDCProviderTypeGoogle:
		return "Google"
	case OIDCProviderTypeMicrosoft:
		return "Microsoft"
	case OIDCProviderTypeGitHub:
		return "GitHub"
	case OIDCProviderTypeOkta:
		return "Okta"
	default:
		return string(p)
	}
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate validates the login request
func (r *LoginRequest) Validate(ctx context.Context) error {
	if !emailRegex.MatchString(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	if r.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}

// LoginResponse represents the login response
// Note: refresh_token is sent via HTTP-only cookie, not in JSON body
type LoginResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"` // seconds until access token expires
}

// LogoutResponse represents the logout response
type LogoutResponse struct {
	Message string `json:"message"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status string `json:"status"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// CreateUserRequest represents the request to create a user
type CreateUserRequest struct {
	Email    string      `json:"email"`
	TenantID uuid.UUID   `json:"tenant_id"`
	RoleIDs  []uuid.UUID `json:"role_ids,omitempty"` // Optional list of role IDs to assign
}

// Validate validates the create user request
func (r *CreateUserRequest) Validate(ctx context.Context) error {
	if !emailRegex.MatchString(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	if r.TenantID == uuid.Nil {
		return fmt.Errorf("tenant_id is required")
	}
	return nil
}

// CreateUserResponse represents the response from creating a user
type CreateUserResponse struct {
	UserID            uuid.UUID `json:"user_id"`
	Email             string    `json:"email"`
	TenantID          uuid.UUID `json:"tenant_id"`
	VerificationToken string    `json:"verification_token"` // Empty for SSO users, set for non-SSO users
}

// RegisterRequest represents the registration request body
// Password is set during email verification, not during initial registration
type RegisterRequest struct {
	Email string `json:"email"`
}

// Validate validates the registration request
func (r *RegisterRequest) Validate(ctx context.Context) error {
	if !emailRegex.MatchString(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// RegisterResponse represents the registration response
type RegisterResponse struct {
	UserID  uuid.UUID `json:"user_id"`
	Email   string    `json:"email"`
	Message string    `json:"message"`
}

// VerifyEmailRequest represents the email verification request body
// User proves email ownership and sets their password
type VerifyEmailRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// Validate validates the verify email request
func (r *VerifyEmailRequest) Validate(ctx context.Context) error {
	if r.Token == "" {
		return fmt.Errorf("token is required")
	}
	if r.Password == "" {
		return fmt.Errorf("password is required")
	}

	// Validate password against security policy
	return password.NewValidator().Validate(ctx, r.Password)
}

// ForgotPasswordRequest represents the forgot password request body
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// Validate validates the forgot password request
func (r *ForgotPasswordRequest) Validate(ctx context.Context) error {
	if !emailRegex.MatchString(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// ForgotPasswordResponse represents the forgot password response
type ForgotPasswordResponse struct {
	Message string `json:"message"`
}

// ResetPasswordRequest represents the reset password request body
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// Validate validates the reset password request
func (r *ResetPasswordRequest) Validate(ctx context.Context) error {
	if r.Token == "" {
		return fmt.Errorf("token is required")
	}
	if r.NewPassword == "" {
		return fmt.Errorf("new password is required")
	}

	// Validate password against security policy
	return password.NewValidator().Validate(ctx, r.NewPassword)
}

// ResetPasswordResponse represents the reset password response
type ResetPasswordResponse struct {
	Message string `json:"message"`
}

// User represents a user in API responses
type User struct {
	ID     uuid.UUID `json:"id"`
	Email  string    `json:"email"`
	Status string    `json:"status"`
}

// OIDCLoginRequest represents the individual OAuth login request body
type OIDCLoginRequest struct {
	ProviderType OIDCProviderType `json:"provider_type"`
}

// Validate validates the OIDC login request
func (r *OIDCLoginRequest) Validate(ctx context.Context) error {
	if !r.ProviderType.IsValid() {
		return fmt.Errorf("invalid provider_type: must be one of google, microsoft, github, or okta")
	}
	return nil
}

// SSOLoginRequest represents the corporate SSO login request body
type SSOLoginRequest struct {
	Email string `json:"email"`
}

// Validate validates the SSO login request
func (r *SSOLoginRequest) Validate(ctx context.Context) error {
	if !emailRegex.MatchString(r.Email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// OIDCAuthResponse represents the OIDC authentication response with authorization URL
type OIDCAuthResponse struct {
	AuthorizationURL string `json:"authorization_url"`
}

// OIDCProvider represents an OIDC provider configuration (includes secrets)
type OIDCProvider struct {
	ID                       uuid.UUID              `json:"id"`
	ProviderName             string                 `json:"provider_name"`
	IssuerURL                string                 `json:"issuer_url"`
	ClientID                 string                 `json:"client_id"`
	Scopes                   []string               `json:"scopes"`
	Enabled                  bool                   `json:"enabled"`
	AllowedDomains           []string               `json:"allowed_domains"`
	AutoCreateUsers          bool                   `json:"auto_create_users"`
	RequireEmailVerification bool                   `json:"require_email_verification"`
	RegistrationMethod       OIDCRegistrationMethod `json:"registration_method"`
	ClientIDIssuedAt         *time.Time             `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt    *time.Time             `json:"client_secret_expires_at,omitempty"`
	CreatedAt                time.Time              `json:"created_at"`
	UpdatedAt                time.Time              `json:"updated_at"`
}

// CreateOIDCProviderRequest represents the request to create an OIDC provider
type CreateOIDCProviderRequest struct {
	ProviderName             string   `json:"provider_name"`
	IssuerURL                string   `json:"issuer_url"`
	ClientID                 string   `json:"client_id,omitempty"`     // Optional: for manual registration
	ClientSecret             string   `json:"client_secret,omitempty"` // Optional: for manual registration
	AccessToken              string   `json:"access_token,omitempty"`  // Optional: for authenticated dynamic registration
	Scopes                   []string `json:"scopes,omitempty"`
	Enabled                  bool     `json:"enabled"`
	AllowedDomains           []string `json:"allowed_domains"`
	AutoCreateUsers          bool     `json:"auto_create_users"`
	RequireEmailVerification bool     `json:"require_email_verification"`
}

// Validate validates the create OIDC provider request
func (r *CreateOIDCProviderRequest) Validate(ctx context.Context) error {
	if r.ProviderName == "" {
		return fmt.Errorf("provider_name is required")
	}
	if r.IssuerURL == "" {
		return fmt.Errorf("issuer_url is required")
	}

	// HTTPS required for production security, but allow HTTP for localhost/testing
	isHTTPS := strings.HasPrefix(r.IssuerURL, "https://")
	isLocalhost := strings.HasPrefix(r.IssuerURL, "http://localhost") ||
		strings.HasPrefix(r.IssuerURL, "http://127.0.0.1") ||
		strings.HasPrefix(r.IssuerURL, "http://oidc-mock")

	if !isHTTPS && !isLocalhost {
		return fmt.Errorf("issuer_url must use HTTPS")
	}
	// ClientID and ClientSecret must be provided together (manual) or both omitted (dynamic)
	if (r.ClientID != "" && r.ClientSecret == "") || (r.ClientID == "" && r.ClientSecret != "") {
		return fmt.Errorf("client_id and client_secret are both required for manual registration")
	}
	if len(r.AllowedDomains) == 0 {
		return fmt.Errorf("at least one allowed domain is required for corporate SSO")
	}
	return nil
}

// GetOIDCProviderRequest represents the request to get an OIDC provider by ID
type GetOIDCProviderRequest struct {
	ProviderID uuid.UUID `json:"-"` // From URL parameter
}

// Validate validates the get OIDC provider request
func (r *GetOIDCProviderRequest) Validate(ctx context.Context) error {
	if r.ProviderID == uuid.Nil {
		return fmt.Errorf("provider_id is required")
	}
	return nil
}

// UpdateOIDCProviderRequest represents the request to update an OIDC provider
// All fields are optional pointers to support partial updates
type UpdateOIDCProviderRequest struct {
	ProviderID               uuid.UUID `json:"-"`                                    // From URL parameter, not JSON body
	ProviderName             *string   `json:"provider_name,omitempty"`              // Optional: update display name
	ClientSecret             *string   `json:"client_secret,omitempty"`              // Optional: rotate secret
	Scopes                   []string  `json:"scopes,omitempty"`                     // Optional: nil = keep, [] = clear, non-empty = update
	Enabled                  *bool     `json:"enabled,omitempty"`                    // Optional: update enabled status
	AllowedDomains           []string  `json:"allowed_domains,omitempty"`            // Optional: nil = keep, non-nil = update
	AutoCreateUsers          *bool     `json:"auto_create_users,omitempty"`          // Optional: update auto-create users flag
	RequireEmailVerification *bool     `json:"require_email_verification,omitempty"` // Optional: update email verification requirement
}

// Validate validates the update OIDC provider request
func (r *UpdateOIDCProviderRequest) Validate(ctx context.Context) error {
	if r.ProviderID == uuid.Nil {
		return fmt.Errorf("provider_id is required")
	}

	// If AllowedDomains is provided (non-nil), it must have at least one entry
	// nil means "keep existing", empty slice means "clear" (which we don't allow)
	if r.AllowedDomains != nil && len(r.AllowedDomains) == 0 {
		return fmt.Errorf("allowed_domains cannot be empty (at least one domain required for corporate SSO)")
	}

	return nil
}

// DeleteOIDCProviderRequest represents the request to delete an OIDC provider
type DeleteOIDCProviderRequest struct {
	ProviderID uuid.UUID `json:"-"` // From URL parameter
}

// Validate validates the delete OIDC provider request
func (r *DeleteOIDCProviderRequest) Validate(ctx context.Context) error {
	if r.ProviderID == uuid.Nil {
		return fmt.Errorf("provider_id is required")
	}
	return nil
}

// OIDCProvidersResponse represents the response with a list of OIDC providers
type OIDCProvidersResponse struct {
	Providers []OIDCProvider `json:"providers"`
}

// OIDCProviderTypeInfo represents information about a supported OAuth provider type
type OIDCProviderTypeInfo struct {
	Type        OIDCProviderType `json:"type"`
	DisplayName string           `json:"display_name"`
}

// OIDCProviderTypesResponse represents the response with supported OIDC provider types
type OIDCProviderTypesResponse struct {
	Providers []OIDCProviderTypeInfo `json:"providers"`
}

// RBAC types

// Permission represents a system permission
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

// PermissionsResponse represents the response with a list of permissions
type PermissionsResponse struct {
	Permissions []Permission `json:"permissions"`
}

// Role represents a role with its metadata
type Role struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

// CreateRoleRequest represents the request to create a new role
type CreateRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Validate validates the create role request
func (r *CreateRoleRequest) Validate(ctx context.Context) error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(r.Description) == "" {
		return fmt.Errorf("description is required")
	}
	return nil
}

// UpdateRoleRequest represents the request to update a role
type UpdateRoleRequest struct {
	RoleID      uuid.UUID `json:"-"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

// Validate validates the update role request
func (r *UpdateRoleRequest) Validate(ctx context.Context) error {
	if r.RoleID == uuid.Nil {
		return fmt.Errorf("role_id is required")
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(r.Description) == "" {
		return fmt.Errorf("description is required")
	}
	return nil
}

// GetRoleRequest represents the request to get a role
type GetRoleRequest struct {
	RoleID uuid.UUID `json:"-"`
}

// Validate validates the get role request
func (r *GetRoleRequest) Validate(ctx context.Context) error {
	if r.RoleID == uuid.Nil {
		return fmt.Errorf("role_id is required")
	}
	return nil
}

// DeleteRoleRequest represents the request to delete a role
type DeleteRoleRequest struct {
	RoleID uuid.UUID `json:"-"`
}

// Validate validates the delete role request
func (r *DeleteRoleRequest) Validate(ctx context.Context) error {
	if r.RoleID == uuid.Nil {
		return fmt.Errorf("role_id is required")
	}
	return nil
}

// RolesResponse represents the response with a list of roles
type RolesResponse struct {
	Roles []Role `json:"roles"`
}

// GetRolePermissionsRequest represents the request to get permissions for a role
type GetRolePermissionsRequest struct {
	RoleID uuid.UUID `json:"-"`
}

// Validate validates the get role permissions request
func (r *GetRolePermissionsRequest) Validate(ctx context.Context) error {
	if r.RoleID == uuid.Nil {
		return fmt.Errorf("role_id is required")
	}
	return nil
}

// SetRolePermissionsRequest represents the request to set all permissions for a role
type SetRolePermissionsRequest struct {
	RoleID        uuid.UUID   `json:"-"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

// Validate validates the set role permissions request
func (r *SetRolePermissionsRequest) Validate(ctx context.Context) error {
	if r.RoleID == uuid.Nil {
		return fmt.Errorf("role_id is required")
	}
	return nil
}

// SetUserRolesRequest represents the request to set all roles for a user
type SetUserRolesRequest struct {
	UserID  uuid.UUID   `json:"-"`
	RoleIDs []uuid.UUID `json:"role_ids"`
}

// Validate validates the set user roles request
func (r *SetUserRolesRequest) Validate(ctx context.Context) error {
	if r.UserID == uuid.Nil {
		return fmt.Errorf("user_id is required")
	}
	return nil
}

// GetUserRolesRequest represents the request to get roles for a user
type GetUserRolesRequest struct {
	UserID uuid.UUID `json:"-"`
}

// Validate validates the get user roles request
func (r *GetUserRolesRequest) Validate(ctx context.Context) error {
	if r.UserID == uuid.Nil {
		return fmt.Errorf("user_id is required")
	}
	return nil
}

// EffectivePermission represents a direct permission assigned to a user
type EffectivePermission struct {
	Permission Permission       `json:"permission"`
	Effect     PermissionEffect `json:"effect"`
}

// DirectPermission represents a direct permission to set for a user
type DirectPermission struct {
	PermissionID uuid.UUID        `json:"permission_id"`
	Effect       PermissionEffect `json:"effect"`
}

// SetDirectPermissionsRequest represents the request to set all direct permissions for a user
type SetDirectPermissionsRequest struct {
	UserID      uuid.UUID          `json:"-"`
	Permissions []DirectPermission `json:"permissions"`
}

// Validate validates the set user permissions request
func (r *SetDirectPermissionsRequest) Validate(ctx context.Context) error {
	if r.UserID == uuid.Nil {
		return fmt.Errorf("user_id is required")
	}
	for _, perm := range r.Permissions {
		if perm.PermissionID == uuid.Nil {
			return fmt.Errorf("permission_id is required")
		}
	}
	return nil
}

// GetDirectPermissionsRequest represents the request to get direct permissions for a user
type GetDirectPermissionsRequest struct {
	UserID uuid.UUID `json:"-"`
}

// Validate validates the get user permissions request
func (r *GetDirectPermissionsRequest) Validate(ctx context.Context) error {
	if r.UserID == uuid.Nil {
		return fmt.Errorf("user_id is required")
	}
	return nil
}

// DirectPermissionsResponse represents the response with direct permissions for a user
type DirectPermissionsResponse struct {
	Permissions []EffectivePermission `json:"permissions"`
}
