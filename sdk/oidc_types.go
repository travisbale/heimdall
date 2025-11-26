package sdk

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

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
	return validateEmail(r.Email)
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
	if err := validateRequired(r.ProviderName, "provider_name"); err != nil {
		return err
	}
	if err := validateRequired(r.IssuerURL, "issuer_url"); err != nil {
		return err
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
	return validateUUID(r.ProviderID, "provider_id")
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
	if err := validateUUID(r.ProviderID, "provider_id"); err != nil {
		return err
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
	return validateUUID(r.ProviderID, "provider_id")
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
