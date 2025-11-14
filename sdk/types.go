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

type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

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

// CreateUserRequest represents the request to create a user
type CreateUserRequest struct {
	Email    string    `json:"email"`
	TenantID uuid.UUID `json:"tenant_id"`
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
	TemporaryPassword string    `json:"temporary_password"`
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
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Email    string    `json:"email"`
	Status   string    `json:"status"`
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

// OIDCProviderResponse represents the response with OIDC provider details
type OIDCProviderResponse struct {
	Provider OIDCProvider `json:"provider"`
}

// ListOIDCProvidersResponse represents the response with list of OIDC providers
type ListOIDCProvidersResponse struct {
	Providers []OIDCProvider `json:"providers"`
}

// SupportedOIDCProviderType represents a supported OAuth provider type
type SupportedOIDCProviderType struct {
	Type        OIDCProviderType `json:"type"`
	DisplayName string           `json:"display_name"`
}

// ListSupportedOIDCProvidersResponse represents the response with supported provider types
type ListSupportedOIDCProvidersResponse struct {
	Providers []SupportedOIDCProviderType `json:"providers"`
}
