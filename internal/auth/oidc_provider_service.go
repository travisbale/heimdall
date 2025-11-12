package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CreateOIDCProvider creates a new OIDC provider configuration manually or dynamically
func (s *OIDCService) CreateOIDCProvider(ctx context.Context, provider *OIDCProviderConfig, accessToken string) (*OIDCProviderConfig, error) {
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
func (s *OIDCService) createManualOIDCProvider(ctx context.Context, provider *OIDCProviderConfig) (*OIDCProviderConfig, error) {
	// Validate that the issuer is reachable by creating a provider instance
	_, err := s.providerFactory.NewProvider(ctx, provider.IssuerURL, provider.ClientID, provider.ClientSecret, provider.Scopes)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed (issuer unreachable): %w", err)
	}

	provider.RegistrationMethod = OIDCRegistrationMethodManual

	// Store in database
	return s.oidcProviderDB.CreateOIDCProvider(ctx, provider)
}

// createDynamicOIDCProvider handles dynamic OIDC provider registration (RFC 7591)
func (s *OIDCService) createDynamicOIDCProvider(ctx context.Context, provider *OIDCProviderConfig, accessToken string) (*OIDCProviderConfig, error) {
	s.logger.Info("performing OIDC discovery for dynamic registration", "issuer_url", provider.IssuerURL)

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
	provider.RegistrationMethod = OIDCRegistrationMethodDynamic

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

	// Store in database
	return s.oidcProviderDB.CreateOIDCProvider(ctx, provider)
}

// GetOIDCProvider retrieves an OIDC provider by ID (admin operation)
func (s *OIDCService) GetOIDCProvider(ctx context.Context, providerID uuid.UUID) (*OIDCProviderConfig, error) {
	return s.oidcProviderDB.GetOIDCProviderByID(ctx, providerID)
}

// ListOIDCProviders lists all OIDC providers for a tenant (admin operation)
func (s *OIDCService) ListOIDCProviders(ctx context.Context) ([]*OIDCProviderConfig, error) {
	return s.oidcProviderDB.ListOIDCProviders(ctx)
}

// UpdateOIDCProvider updates an OIDC provider configuration (admin operation)
func (s *OIDCService) UpdateOIDCProvider(ctx context.Context, params *UpdateOIDCProviderParams) (*OIDCProviderConfig, error) {
	// RLS automatically enforces tenant isolation at the database layer
	// If the provider doesn't exist or doesn't belong to this tenant, ErrOIDCProviderNotFound will be returned
	return s.oidcProviderDB.UpdateOIDCProvider(ctx, params)
}

// DeleteOIDCProvider deletes an OIDC provider (admin operation)
// For dynamically registered providers, also attempts to unregister the OAuth client
func (s *OIDCService) DeleteOIDCProvider(ctx context.Context, providerID uuid.UUID) error {
	// Verify the provider belongs to this tenant by fetching it first
	// (RLS will automatically enforce tenant isolation)
	provider, err := s.oidcProviderDB.GetOIDCProviderByID(ctx, providerID)
	if err != nil {
		return err
	}

	// Only attempt to unregister dynamically registered clients
	// Manually registered clients must be cleaned up by the admin at the IdP
	if provider.RegistrationMethod == OIDCRegistrationMethodDynamic &&
		provider.RegistrationClientURI != "" {

		s.logger.Info("unregistering dynamically registered OAuth client", "client_id", provider.ClientID, "issuer_url", provider.IssuerURL)
		if err := s.registrationClient.Unregister(ctx, provider.RegistrationClientURI, provider.RegistrationAccessToken); err != nil {
			s.logger.Error("failed to unregister OAuth client (continuing with deletion)", "error", err, "client_id", provider.ClientID)
		} else {
			s.logger.Info("OAuth client unregistered successfully", "client_id", provider.ClientID)
		}
	} else if provider.RegistrationMethod == OIDCRegistrationMethodManual {
		s.logger.Info("deleting manually registered OIDC provider (client must be cleaned up manually at IdP)", "client_id", provider.ClientID, "issuer_url", provider.IssuerURL)
	}

	return s.oidcProviderDB.DeleteOIDCProviderByID(ctx, providerID)
}
