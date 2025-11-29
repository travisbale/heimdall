package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/heimdall/sdk"
)

// OIDCProviderServiceConfig holds the dependencies for creating an OIDCProviderService
type OIDCProviderServiceConfig struct {
	OIDCProviderDB     oidcProviderDB
	RegistrationClient oidcRegistrationClient
	ProviderFactory    oidcProviderFactory
	PublicURL          string
	Logger             logger
}

// OIDCProviderService handles OIDC provider CRUD operations and domain checks
type OIDCProviderService struct {
	oidcProviderDB     oidcProviderDB
	registrationClient oidcRegistrationClient
	providerFactory    oidcProviderFactory
	publicURL          string
	logger             logger
}

// NewOIDCProviderService creates a new OIDCProviderService
func NewOIDCProviderService(config *OIDCProviderServiceConfig) *OIDCProviderService {
	return &OIDCProviderService{
		oidcProviderDB:     config.OIDCProviderDB,
		registrationClient: config.RegistrationClient,
		providerFactory:    config.ProviderFactory,
		publicURL:          config.PublicURL,
		logger:             config.Logger,
	}
}

// getCallbackURL returns the full OAuth callback URL
func (s *OIDCProviderService) getCallbackURL() string {
	return s.publicURL + sdk.RouteV1OAuthCallback
}

// CreateOIDCProvider creates a new OIDC provider configuration manually or dynamically
func (s *OIDCProviderService) CreateOIDCProvider(ctx context.Context, provider *OIDCProviderConfig, accessToken string) (*OIDCProviderConfig, error) {
	if len(provider.Scopes) == 0 {
		provider.Scopes = defaultOIDCScopes
	}

	if provider.ClientID != "" && provider.ClientSecret != "" {
		// Manual registration - credentials provided by admin
		return s.createManualOIDCProvider(ctx, provider)
	}

	// Dynamic registration - perform OIDC discovery and RFC 7591 client registration
	return s.createDynamicOIDCProvider(ctx, provider, accessToken)
}

// createManualOIDCProvider handles manual OIDC provider registration
func (s *OIDCProviderService) createManualOIDCProvider(ctx context.Context, provider *OIDCProviderConfig) (*OIDCProviderConfig, error) {
	// Validate that the issuer is reachable by creating a provider instance
	_, err := s.providerFactory.NewProvider(ctx, provider.IssuerURL, provider.ClientID, provider.ClientSecret, provider.Scopes)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed (issuer unreachable): %w", err)
	}

	provider.RegistrationMethod = sdk.OIDCRegistrationMethodManual

	provider, err = s.oidcProviderDB.CreateOIDCProvider(ctx, provider)
	if err != nil {
		return nil, err
	}

	s.logger.AuditContext(ctx, events.OIDCProviderCreated,
		"provider_id", provider.ID,
		"provider_name", provider.ProviderName,
		"registration_method", "manual",
	)

	return provider, nil
}

// createDynamicOIDCProvider handles dynamic OIDC provider registration (RFC 7591)
func (s *OIDCProviderService) createDynamicOIDCProvider(ctx context.Context, provider *OIDCProviderConfig, accessToken string) (*OIDCProviderConfig, error) {
	// Perform OIDC discovery
	metadata, err := s.registrationClient.Discover(ctx, provider.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	// Perform dynamic client registration (RFC 7591)
	callbackURL := s.getCallbackURL()
	clientName := fmt.Sprintf("Heimdall - %s", provider.ProviderName)

	registration, err := s.registrationClient.Register(ctx, metadata.RegistrationEndpoint, callbackURL, clientName, accessToken, provider.Scopes)
	if err != nil {
		return nil, fmt.Errorf("dynamic client registration failed: %w", err)
	}

	// Populate provider with registration response
	provider.ClientID = registration.ClientID
	provider.ClientSecret = registration.ClientSecret
	provider.RegistrationMethod = sdk.OIDCRegistrationMethodDynamic

	if registration.RegistrationAccessToken != "" {
		provider.RegistrationAccessToken = registration.RegistrationAccessToken
	}
	if registration.RegistrationClientURI != "" {
		provider.RegistrationClientURI = registration.RegistrationClientURI
	}

	// Convert Unix timestamps to time.Time if provided
	if registration.ClientIDIssuedAt != nil {
		issuedAt := time.Unix(*registration.ClientIDIssuedAt, 0)
		provider.ClientIDIssuedAt = &issuedAt
	}

	if registration.ClientSecretExpiresAt != nil && *registration.ClientSecretExpiresAt != 0 {
		expiresAt := time.Unix(*registration.ClientSecretExpiresAt, 0)
		provider.ClientSecretExpiresAt = &expiresAt
	}

	provider, err = s.oidcProviderDB.CreateOIDCProvider(ctx, provider)
	if err != nil {
		return nil, err
	}

	s.logger.AuditContext(ctx, events.OIDCProviderCreated,
		"provider_id", provider.ID,
		"provider_name", provider.ProviderName,
		"registration_method", "dynamic",
	)

	return provider, nil
}

// GetOIDCProvider retrieves an OIDC provider by ID
func (s *OIDCProviderService) GetOIDCProvider(ctx context.Context, providerID uuid.UUID) (*OIDCProviderConfig, error) {
	return s.oidcProviderDB.GetOIDCProviderByID(ctx, providerID)
}

// ListOIDCProviders lists all OIDC providers for a tenant
func (s *OIDCProviderService) ListOIDCProviders(ctx context.Context) ([]*OIDCProviderConfig, error) {
	return s.oidcProviderDB.ListOIDCProviders(ctx)
}

// UpdateOIDCProvider updates an OIDC provider configuration
func (s *OIDCProviderService) UpdateOIDCProvider(ctx context.Context, params *UpdateOIDCProviderParams) (*OIDCProviderConfig, error) {
	provider, err := s.oidcProviderDB.UpdateOIDCProvider(ctx, params)
	if err != nil {
		return nil, err
	}

	s.logger.AuditContext(ctx, events.OIDCProviderUpdated, "provider_id", provider.ID, "provider_name", provider.ProviderName)

	return provider, nil
}

// DeleteOIDCProvider deletes an OIDC provider (admin operation)
// For dynamically registered providers, also attempts to unregister the OAuth client
func (s *OIDCProviderService) DeleteOIDCProvider(ctx context.Context, providerID uuid.UUID) error {
	provider, err := s.oidcProviderDB.GetOIDCProviderByID(ctx, providerID)
	if err != nil {
		return err
	}

	// Only attempt to unregister dynamically registered clients
	// Manually registered clients must be cleaned up by the admin at the IdP
	if provider.RegistrationMethod == sdk.OIDCRegistrationMethodDynamic && provider.RegistrationClientURI != "" {
		if err := s.registrationClient.Unregister(ctx, provider.RegistrationClientURI, provider.RegistrationAccessToken); err != nil {
			s.logger.ErrorContext(ctx, "failed to unregister OAuth client (continuing with deletion)", "error", err, "client_id", provider.ClientID)
		} else {
			s.logger.InfoContext(ctx, events.OIDCProviderUnregistered, "client_id", provider.ClientID)
		}
	}

	if err := s.oidcProviderDB.DeleteOIDCProviderByID(ctx, providerID); err != nil {
		return err
	}

	s.logger.AuditContext(ctx, events.OIDCProviderDeleted, "provider_id", providerID, "provider_name", provider.ProviderName)

	return nil
}

// GetOIDCProvidersByDomain retrieves OIDC providers by domain
func (s *OIDCProviderService) GetOIDCProvidersByDomain(ctx context.Context, domain string) ([]*OIDCProviderConfig, error) {
	return s.oidcProviderDB.GetOIDCProvidersByDomain(ctx, domain)
}

// IsSSORequired verifies if SSO login is required for the email domain
func (s *OIDCProviderService) IsSSORequired(ctx context.Context, email string) (bool, error) {
	domain, err := extractEmailDomain(email)
	if err != nil {
		return false, fmt.Errorf("invalid email format: %w", err)
	}

	providers, err := s.oidcProviderDB.GetOIDCProvidersByDomain(ctx, domain)
	if err != nil {
		return false, fmt.Errorf("failed to check SSO providers for domain: %w", err)
	}

	if len(providers) > 0 {
		return true, nil
	}

	return false, nil
}
