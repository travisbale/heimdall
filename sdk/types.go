package sdk

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

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

// LoginRequest represents the login request body
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate validates the login request
func (r *LoginRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
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
func (r *CreateUserRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
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
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate validates the registration request
func (r *RegisterRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	if r.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(r.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
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
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// Validate validates the verify email request
func (r *VerifyEmailRequest) Validate() error {
	if r.Token == "" {
		return fmt.Errorf("token is required")
	}
	return nil
}

// ResendVerificationRequest represents the resend verification email request body
type ResendVerificationRequest struct {
	Email string `json:"email"`
}

// Validate validates the resend verification request
func (r *ResendVerificationRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	return nil
}

// ResendVerificationResponse represents the response from resending verification email
type ResendVerificationResponse struct {
	Message string `json:"message"`
}

// ForgotPasswordRequest represents the forgot password request body
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// Validate validates the forgot password request
func (r *ForgotPasswordRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
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
func (r *ResetPasswordRequest) Validate() error {
	if r.Token == "" {
		return fmt.Errorf("token is required")
	}
	if r.NewPassword == "" {
		return fmt.Errorf("new password is required")
	}
	if len(r.NewPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	return nil
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
func (r *OIDCLoginRequest) Validate() error {
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
func (r *SSOLoginRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	// Basic email validation
	if !strings.Contains(r.Email, "@") {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// OIDCLinkRequest represents the OIDC link request body
type OIDCLinkRequest struct {
	ProviderID uuid.UUID `json:"provider_id"`
}

// Validate validates the OIDC link request
func (r *OIDCLinkRequest) Validate() error {
	if r.ProviderID == uuid.Nil {
		return fmt.Errorf("provider_id is required")
	}
	return nil
}

// OIDCAuthResponse represents the OIDC authentication response with authorization URL
// Used for both login and link flows as they return identical responses
type OIDCAuthResponse struct {
	AuthorizationURL string `json:"authorization_url"`
}

// OIDCCallbackRequest represents the OIDC callback query parameters
type OIDCCallbackRequest struct {
	State            string `json:"state"`
	Code             string `json:"code"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Validate validates the OIDC callback request
func (r *OIDCCallbackRequest) Validate() error {
	// If there's an error from the OIDC provider, that's valid
	// (we'll handle it in the handler)
	if r.Error != "" {
		return nil
	}

	// For success case, both state and code are required
	if r.State == "" {
		return fmt.Errorf("state is required")
	}
	if r.Code == "" {
		return fmt.Errorf("code is required")
	}
	return nil
}

// OIDCLink represents an OIDC provider link
type OIDCLink struct {
	ID            uuid.UUID  `json:"id"`
	ProviderID    uuid.UUID  `json:"provider_id"`
	ProviderName  string     `json:"provider_name"` // Display name for the linked provider
	ProviderEmail string     `json:"provider_email"`
	LinkedAt      time.Time  `json:"linked_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
}

// OIDCLinkResponse represents the response from linking an OIDC provider
type OIDCLinkResponse struct {
	Link OIDCLink `json:"link"`
}

// OIDCUnlinkRequest represents the request to unlink an OIDC provider
type OIDCUnlinkRequest struct {
	ProviderID uuid.UUID `json:"-"` // From URL parameter
}

// Validate validates the OIDC unlink request
func (r *OIDCUnlinkRequest) Validate() error {
	if r.ProviderID == uuid.Nil {
		return fmt.Errorf("provider_id is required")
	}
	return nil
}

// OIDCListLinksResponse represents the response from listing OIDC provider links
type OIDCListLinksResponse struct {
	Links []OIDCLink `json:"links"`
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
func (r *CreateOIDCProviderRequest) Validate() error {
	if r.ProviderName == "" {
		return fmt.Errorf("provider_name is required")
	}
	if r.IssuerURL == "" {
		return fmt.Errorf("issuer_url is required")
	}
	// Basic URL validation
	if !strings.HasPrefix(r.IssuerURL, "https://") {
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
func (r *GetOIDCProviderRequest) Validate() error {
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
func (r *UpdateOIDCProviderRequest) Validate() error {
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
func (r *DeleteOIDCProviderRequest) Validate() error {
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
