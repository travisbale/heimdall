package sdk

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type OIDCProviderType string

const (
	OIDCProviderTypeGoogle    OIDCProviderType = "google"
	OIDCProviderTypeMicrosoft OIDCProviderType = "microsoft"
	OIDCProviderTypeGitHub    OIDCProviderType = "github"
	OIDCProviderTypeOkta      OIDCProviderType = "okta"
)

// OIDCRegistrationMethod is whether a provider was registered by hand or discovered.
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

// OIDCLoginRequest signs in through a personal account (Google, GitHub), not corporate SSO.
type OIDCLoginRequest struct {
	ProviderType OIDCProviderType `json:"provider_type"`
}

func (r *OIDCLoginRequest) Validate(ctx context.Context) error {
	if !r.ProviderType.IsValid() {
		return fmt.Errorf("invalid provider_type: must be one of google, microsoft, github, or okta")
	}
	return nil
}

// SSOLoginRequest signs in through the provider configured for the address's domain. The
// address is a hint for choosing that provider; the identity comes from the provider.
type SSOLoginRequest struct {
	Email string `json:"email"`
}

func (r *SSOLoginRequest) Validate(ctx context.Context) error {
	return validateEmail(r.Email)
}

// OIDCAuthResponse is where to send the browser to begin the flow.
type OIDCAuthResponse struct {
	AuthorizationURL string `json:"authorization_url"`
}

// OIDCProvider is a provider configuration including its client secret, so it is only ever
// returned to a caller holding an OIDC read scope.
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
		strings.Contains(r.IssuerURL, "oidc-mock")

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

type GetOIDCProviderRequest struct {
	ProviderID uuid.UUID `json:"-"` // From URL parameter
}

func (r *GetOIDCProviderRequest) Validate(ctx context.Context) error {
	return validateUUID(r.ProviderID, "provider_id")
}

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

func (r *UpdateOIDCProviderRequest) Validate(ctx context.Context) error {
	if err := validateUUID(r.ProviderID, "provider_id"); err != nil {
		return err
	}

	// nil keeps what is there; an empty slice would mean clear, which is not allowed.
	if r.AllowedDomains != nil && len(r.AllowedDomains) == 0 {
		return fmt.Errorf("allowed_domains cannot be empty (at least one domain required for corporate SSO)")
	}

	return nil
}

type DeleteOIDCProviderRequest struct {
	ProviderID uuid.UUID `json:"-"` // From URL parameter
}

func (r *DeleteOIDCProviderRequest) Validate(ctx context.Context) error {
	return validateUUID(r.ProviderID, "provider_id")
}

type OIDCProvidersResponse struct {
	Providers []OIDCProvider `json:"providers"`
}

type OIDCProviderTypeInfo struct {
	Type        OIDCProviderType `json:"type"`
	DisplayName string           `json:"display_name"`
}

type OIDCProviderTypesResponse struct {
	Providers []OIDCProviderTypeInfo `json:"providers"`
}
