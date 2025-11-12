package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// defaultOIDCScopes are the standard OIDC scopes requested by default
var defaultOIDCScopes = []string{"openid", "email", "profile"}

// oidcProviderDB defines the interface for OIDC provider database operations
type oidcProviderDB interface {
	CreateOIDCProvider(ctx context.Context, provider *OIDCProviderConfig) (*OIDCProviderConfig, error)
	GetOIDCProviderByID(ctx context.Context, id uuid.UUID) (*OIDCProviderConfig, error)
	GetOIDCProvidersByDomain(ctx context.Context, domain string) ([]*OIDCProviderConfig, error)
	ListOIDCProviders(ctx context.Context) ([]*OIDCProviderConfig, error)
	UpdateOIDCProvider(ctx context.Context, params *UpdateOIDCProviderParams) (*OIDCProviderConfig, error)
	DeleteOIDCProviderByID(ctx context.Context, id uuid.UUID) error
}

// oidcLinkDB defines the interface for OIDC link database operations
type oidcLinkDB interface {
	CreateOIDCLink(ctx context.Context, link *OIDCLink) (*OIDCLink, error)
	GetOIDCLinkByProvider(ctx context.Context, providerID uuid.UUID, providerUserID string) (*OIDCLink, error)
	GetOIDCLinkByUser(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) (*OIDCLink, error)
	ListOIDCLinksByUser(ctx context.Context, userID uuid.UUID) ([]*OIDCLink, error)
	UpdateOIDCLinkLastUsed(ctx context.Context, id uuid.UUID) error
	DeleteOIDCLink(ctx context.Context, id uuid.UUID) error
}

// oidcSessionDB defines the interface for OIDC session database operations
type oidcSessionDB interface {
	CreateOIDCSession(ctx context.Context, session *OIDCSession) (*OIDCSession, error)
	GetOIDCSessionByState(ctx context.Context, state string) (*OIDCSession, error)
	DeleteOIDCSession(ctx context.Context, id uuid.UUID) error
	DeleteExpiredOIDCSessions(ctx context.Context) error
}

// oidcRegistrationClient defines the interface for OIDC discovery and dynamic registration
type oidcRegistrationClient interface {
	Discover(ctx context.Context, issuerURL string) (*OIDCDiscoveryMetadata, error)
	Register(ctx context.Context, registrationEndpoint, callbackURL, clientName, accessToken string, scopes []string) (*OIDCRegistration, error)
	Unregister(ctx context.Context, registrationClientURI, registrationAccessToken string) error
}

// oidcProviderFactory creates OIDC provider instances from configuration
type oidcProviderFactory interface {
	NewProvider(ctx context.Context, issuerURL, clientID, clientSecret string, scopes []string) (OIDCProvider, error)
}

// OIDCServiceConfig holds the dependencies for creating an OIDCService
type OIDCServiceConfig struct {
	OIDCProviderDB     oidcProviderDB
	OIDCLinkDB         oidcLinkDB
	OIDCSessionDB      oidcSessionDB
	UserDB             userDB
	SystemProviders    map[string]OIDCProvider // System-wide providers for public login (from env vars)
	RegistrationClient oidcRegistrationClient  // Client for OIDC discovery and dynamic registration
	ProviderFactory    oidcProviderFactory     // Factory for creating provider instances
	PublicURL          string
	Logger             logger
}

// OIDCService handles OIDC business logic
type OIDCService struct {
	oidcProviderDB     oidcProviderDB
	oidcLinkDB         oidcLinkDB
	oidcSessionDB      oidcSessionDB
	userDB             userDB
	systemProviders    map[string]OIDCProvider // System-wide providers for public login
	registrationClient oidcRegistrationClient
	providerFactory    oidcProviderFactory
	publicURL          string
	logger             logger
}

// NewOIDCService creates a new OIDC service
func NewOIDCService(config *OIDCServiceConfig) *OIDCService {
	return &OIDCService{
		oidcProviderDB:     config.OIDCProviderDB,
		oidcLinkDB:         config.OIDCLinkDB,
		oidcSessionDB:      config.OIDCSessionDB,
		userDB:             config.UserDB,
		systemProviders:    config.SystemProviders,
		registrationClient: config.RegistrationClient,
		providerFactory:    config.ProviderFactory,
		publicURL:          config.PublicURL,
		logger:             config.Logger,
	}
}

// StartSSOLogin initiates a corporate SSO login flow (public, unauthenticated)
// Auto-detects the OIDC provider based on the domain.
func (s *OIDCService) StartSSOLogin(ctx context.Context, domain string) (string, error) {
	// Find corporate provider for this domain (auto-detect)
	providerConfigs, err := s.oidcProviderDB.GetOIDCProvidersByDomain(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("failed to lookup SSO provider: %w", err)
	}

	if len(providerConfigs) == 0 {
		return "", ErrSSONotConfigured
	}

	// Use the first enabled provider config
	providerConfig := providerConfigs[0]

	// Create corporate provider instance
	provider, err := s.providerFactory.NewProvider(
		ctx,
		providerConfig.IssuerURL,
		providerConfig.ClientID,
		providerConfig.ClientSecret,
		providerConfig.Scopes, // Scopes already set by CreateOIDCProvider
	)
	if err != nil {
		return "", fmt.Errorf("failed to initialize SSO provider: %w", err)
	}

	// Generate CSRF state token (32 bytes, base64 encoded)
	state, err := generateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state token: %w", err)
	}

	// Generate PKCE code verifier (32 bytes, base64 encoded)
	codeVerifier, err := generateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Create OIDC session for SSO login
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   codeVerifier,
		OIDCProviderID: &providerConfig.ID, // Corporate SSO - reference provider config
		ProviderType:   nil,                // Not a system-wide provider
		RedirectURI:    fmt.Sprintf("%s%s", s.publicURL, sdk.RouteV1OAuthCallback),
		TenantID:       &providerConfig.TenantID, // Corporate SSO - store tenant ID
		UserID:         nil,                      // No user ID for login operations
		ExpiresAt:      time.Now().Add(15 * time.Minute),
		Operation:      "login",
	}

	_, err = s.oidcSessionDB.CreateOIDCSession(ctx, session)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC session: %w", err)
	}

	// Use scopes from provider configuration
	authURL, err := provider.GetAuthorizationURL(state, codeVerifier, session.RedirectURI, providerConfig.Scopes)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization URL: %w", err)
	}

	return authURL, nil
}

// StartOIDCLogin initiates an individual OAuth login flow (public, unauthenticated)
// Uses system-wide provider. The tenant will be determined during the callback
// based on the user's email domain or a new tenant will be created.
func (s *OIDCService) StartOIDCLogin(ctx context.Context, providerType sdk.OIDCProviderType) (string, error) {
	// Use system-wide provider for individual OAuth registration
	oidcProvider, ok := s.systemProviders[string(providerType)]
	if !ok {
		return "", fmt.Errorf("OAuth provider not configured: %s", providerType)
	}

	s.logger.Info("starting individual OAuth login", "provider", providerType)

	// Generate CSRF state token (32 bytes, base64 encoded)
	state, err := generateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state token: %w", err)
	}

	// Generate PKCE code verifier (32 bytes, base64 encoded)
	codeVerifier, err := generateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Create OIDC session for individual OAuth login
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   codeVerifier,
		OIDCProviderID: nil,           // Not a tenant-specific provider
		ProviderType:   &providerType, // System-wide provider (Google, GitHub, etc.)
		RedirectURI:    fmt.Sprintf("%s%s", s.publicURL, sdk.RouteV1OAuthCallback),
		TenantID:       nil, // Tenant determined during callback
		UserID:         nil, // No user ID for login operations
		ExpiresAt:      time.Now().Add(15 * time.Minute),
		Operation:      "login",
	}

	_, err = s.oidcSessionDB.CreateOIDCSession(ctx, session)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC session: %w", err)
	}

	// Use default OIDC scopes
	scopes := defaultOIDCScopes

	authURL, err := oidcProvider.GetAuthorizationURL(state, codeVerifier, session.RedirectURI, scopes)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization URL: %w", err)
	}

	return authURL, nil
}

// StartOIDCLink initiates an OIDC link flow for an authenticated user
// Uses tenant-specific provider credentials from the database configuration.
func (s *OIDCService) StartOIDCLink(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) (string, error) {
	// Get the tenant-specific provider configuration from database
	providerConfig, err := s.oidcProviderDB.GetOIDCProviderByID(ctx, providerID)
	if err != nil {
		return "", fmt.Errorf("failed to get OIDC provider configuration: %w", err)
	}

	// Check if provider is enabled
	if !providerConfig.Enabled {
		return "", fmt.Errorf("OIDC provider is disabled: %s", providerConfig.ProviderName)
	}

	// Create provider instance from tenant configuration
	oidcProvider, err := s.providerFactory.NewProvider(
		ctx,
		providerConfig.IssuerURL,
		providerConfig.ClientID,
		providerConfig.ClientSecret,
		providerConfig.Scopes, // Scopes already set by CreateOIDCProvider
	)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Generate CSRF state token (32 bytes, base64 encoded)
	state, err := generateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state token: %w", err)
	}

	// Generate PKCE code verifier (32 bytes, base64 encoded)
	codeVerifier, err := generateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Create OIDC session for link
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   codeVerifier,
		OIDCProviderID: &providerConfig.ID, // Tenant-specific provider
		ProviderType:   nil,                // Not a system-wide provider
		RedirectURI:    fmt.Sprintf("%s%s", s.publicURL, sdk.RouteV1OAuthCallback),
		TenantID:       &providerConfig.TenantID, // Use tenant from provider config
		UserID:         &userID,                  // Store user ID for link operation
		ExpiresAt:      time.Now().Add(15 * time.Minute),
		Operation:      "link",
	}

	_, err = s.oidcSessionDB.CreateOIDCSession(ctx, session)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC session: %w", err)
	}

	// Generate authorization URL with tenant-specific scopes
	authURL, err := oidcProvider.GetAuthorizationURL(state, codeVerifier, session.RedirectURI, providerConfig.Scopes)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization URL: %w", err)
	}

	return authURL, nil
}

// HandleOIDCCallback handles the OIDC callback after user authorization
func (s *OIDCService) HandleOIDCCallback(ctx context.Context, state, code string) (*User, *OIDCLink, error) {
	// Get the OIDC session by state
	session, err := s.oidcSessionDB.GetOIDCSessionByState(ctx, state)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid or expired state: %w", err)
	}

	// Get the appropriate OIDC provider based on session type
	var oidcProvider OIDCProvider
	var providerConfig *OIDCProviderConfig

	if session.OIDCProviderID != nil {
		// For tenant-specific provider (corporate SSO or link operations)
		var err error
		providerConfig, err = s.oidcProviderDB.GetOIDCProviderByID(ctx, *session.OIDCProviderID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get tenant OIDC provider: %w", err)
		}

		oidcProvider, err = s.providerFactory.NewProvider(
			ctx,
			providerConfig.IssuerURL,
			providerConfig.ClientID,
			providerConfig.ClientSecret,
			providerConfig.Scopes, // Scopes already set by CreateOIDCProvider
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create tenant provider: %w", err)
		}
	} else if session.ProviderType != nil {
		// For system-wide provider (individual OAuth login)
		var ok bool
		oidcProvider, ok = s.systemProviders[string(*session.ProviderType)]
		if !ok {
			return nil, nil, fmt.Errorf("OIDC provider not configured: %s", *session.ProviderType)
		}
	} else {
		return nil, nil, fmt.Errorf("session has neither OIDCProviderID nor ProviderType")
	}

	// Exchange authorization code for tokens
	tokenResponse, err := oidcProvider.ExchangeCode(ctx, code, session.CodeVerifier, session.RedirectURI)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	// Get user info from the provider (required for all providers)
	userInfo, err := oidcProvider.GetUserInfo(ctx, tokenResponse.AccessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Validate ID token if available (OIDC providers only, GitHub doesn't support this)
	var emailVerified bool
	if tokenResponse.IDToken != "" {
		claims, err := oidcProvider.ValidateIDToken(ctx, tokenResponse.IDToken)
		if err != nil {
			// Log but don't fail - some providers (GitHub) don't support ID tokens
			providerName := "unknown"
			if session.OIDCProviderID != nil && providerConfig != nil {
				providerName = providerConfig.ProviderName
			} else if session.ProviderType != nil {
				providerName = string(*session.ProviderType)
			}
			s.logger.Error("failed to validate ID token", "error", err, "provider", providerName)
		} else {
			emailVerified = claims.EmailVerified
		}
	}

	// Fall back to email verification from userInfo if ID token validation failed or wasn't available
	if !emailVerified {
		emailVerified = userInfo.EmailVerified
	}

	// Clean up the OIDC session
	defer func() {
		if err := s.oidcSessionDB.DeleteOIDCSession(ctx, session.ID); err != nil {
			s.logger.Error("failed to delete OIDC session", "error", err)
		}
	}()

	// Check if this provider account is already linked
	// For tenant-specific providers, check by provider ID
	// For system-wide providers, we can't check cross-tenant (skip for now)
	var existingLink *OIDCLink
	if session.OIDCProviderID != nil {
		existingLink, err = s.oidcLinkDB.GetOIDCLinkByProvider(ctx, *session.OIDCProviderID, userInfo.Sub)
		if err != nil && err != ErrOIDCLinkNotFound {
			return nil, nil, fmt.Errorf("failed to check existing OIDC link: %w", err)
		}
	}

	if session.Operation == "link" {
		// Handle link operation
		if session.UserID == nil {
			return nil, nil, fmt.Errorf("link operation missing user ID in session")
		}

		// Link operations must use tenant-specific providers
		if session.OIDCProviderID == nil {
			return nil, nil, fmt.Errorf("link operation requires tenant-specific provider")
		}

		// Check if this provider is already linked to another user
		if existingLink != nil {
			if existingLink.UserID != *session.UserID {
				return nil, nil, ErrOIDCProviderAccountAlreadyLinked
			}
			// Already linked to this user, return existing link
			return nil, existingLink, nil
		}

		// Check if user already has this provider linked
		userExistingLink, err := s.oidcLinkDB.GetOIDCLinkByUser(ctx, *session.UserID, *session.OIDCProviderID)
		if err != nil && err != ErrOIDCLinkNotFound {
			return nil, nil, fmt.Errorf("failed to check user's existing OIDC link: %w", err)
		}
		if userExistingLink != nil {
			return nil, nil, ErrOIDCLinkAlreadyExists
		}

		// Create new OIDC link
		link := &OIDCLink{
			UserID:           *session.UserID,
			OIDCProviderID:   *session.OIDCProviderID,
			ProviderUserID:   userInfo.Sub,
			ProviderEmail:    userInfo.Email,
			ProviderMetadata: userInfo.Metadata,
		}

		link, err = s.oidcLinkDB.CreateOIDCLink(ctx, link)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create OIDC link: %w", err)
		}

		// Return nil user (not needed for link operations), and the link
		return nil, link, nil
	}

	// Handle login operation
	if existingLink != nil {
		// User exists - update last used and return user
		err = s.oidcLinkDB.UpdateOIDCLinkLastUsed(ctx, existingLink.ID)
		if err != nil {
			s.logger.Error("failed to update OIDC link last used", "error", err)
		}

		user, err := s.userDB.GetUserByEmail(ctx, userInfo.Email)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get user: %w", err)
		}

		return user, existingLink, nil
	}

	// New user - check email verification
	if !emailVerified {
		return nil, nil, fmt.Errorf("email not verified by provider")
	}

	// Determine tenant ID based on login type
	var tenantID uuid.UUID
	var linkProviderID uuid.UUID
	var isIndividualRegistration bool

	if session.OIDCProviderID != nil {
		// Corporate SSO login - use tenant from provider config
		if providerConfig == nil {
			return nil, nil, fmt.Errorf("provider config not loaded for corporate SSO")
		}

		// Check if auto-provisioning is enabled
		if !providerConfig.AutoCreateUsers {
			emailDomain := extractEmailDomain(userInfo.Email)
			return nil, nil, fmt.Errorf("automatic user provisioning is not enabled for domain %s", emailDomain)
		}

		// Check if email verification is required
		if providerConfig.RequireEmailVerification && !emailVerified {
			return nil, nil, fmt.Errorf("email verification required but not provided by OIDC provider")
		}

		tenantID = providerConfig.TenantID
		linkProviderID = providerConfig.ID
		s.logger.Info("corporate SSO auto-provisioning", "email", userInfo.Email, "tenant_id", tenantID)
	} else {
		// Individual OAuth login - create new tenant for this user
		tenantID = uuid.New()
		isIndividualRegistration = true

		// For individual OAuth, we can't create a link to a non-existent provider
		// This flow is for system-wide providers which don't have database entries
		// We'll skip link creation for now
		s.logger.Info("individual OAuth registration", "email", userInfo.Email, "new_tenant_id", tenantID)
	}

	// Create user in the determined tenant
	user := &User{
		TenantID: tenantID,
		Email:    userInfo.Email,
		Status:   UserStatusActive, // OIDC users are active immediately (email verified by provider)
	}

	user, err = s.userDB.CreateUser(ctx, user)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Create OIDC link only for corporate SSO (tenant-specific providers)
	var link *OIDCLink
	if session.OIDCProviderID != nil {
		link = &OIDCLink{
			UserID:           user.ID,
			OIDCProviderID:   linkProviderID,
			ProviderUserID:   userInfo.Sub,
			ProviderEmail:    userInfo.Email,
			ProviderMetadata: userInfo.Metadata,
		}

		link, err = s.oidcLinkDB.CreateOIDCLink(ctx, link)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create OIDC link: %w", err)
		}
	}

	if isIndividualRegistration {
		s.logger.Info("created new tenant for individual OIDC user", "user_id", user.ID, "tenant_id", tenantID, "email", userInfo.Email)
	}

	return user, link, nil
}

// UnlinkOIDCProvider removes an OIDC provider link from a user
func (s *OIDCService) UnlinkOIDCProvider(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) error {
	// Get the OIDC link
	link, err := s.oidcLinkDB.GetOIDCLinkByUser(ctx, userID, providerID)
	if err != nil {
		return fmt.Errorf("failed to get OIDC link: %w", err)
	}

	// Delete the link
	err = s.oidcLinkDB.DeleteOIDCLink(ctx, link.ID)
	if err != nil {
		return fmt.Errorf("failed to delete OIDC link: %w", err)
	}

	return nil
}

// ListUserOAuthLinks returns all OIDC provider links for a user
func (s *OIDCService) ListUserOIDCLinks(ctx context.Context, userID uuid.UUID) ([]*OIDCLink, error) {
	links, err := s.oidcLinkDB.ListOIDCLinksByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list OIDC links: %w", err)
	}

	return links, nil
}

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
	callbackURL := fmt.Sprintf("%s%s", s.publicURL, sdk.RouteV1OAuthCallback)
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
		provider.RegistrationAccessToken = &registration.RegistrationAccessToken
	}
	if registration.RegistrationClientURI != "" {
		provider.RegistrationClientURI = &registration.RegistrationClientURI
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
	// Verify the provider belongs to this tenant by fetching it first
	// (RLS will automatically enforce tenant isolation)
	existing, err := s.oidcProviderDB.GetOIDCProviderByID(ctx, params.ID)
	if err != nil {
		return nil, err
	}

	// If we got here, the provider belongs to the tenant (RLS enforced it)
	_ = existing

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
		provider.RegistrationClientURI != nil && *provider.RegistrationClientURI != "" {
		var accessToken string
		if provider.RegistrationAccessToken != nil {
			accessToken = *provider.RegistrationAccessToken
		}

		s.logger.Info("unregistering dynamically registered OAuth client", "client_id", provider.ClientID, "issuer_url", provider.IssuerURL)
		if err := s.registrationClient.Unregister(ctx, *provider.RegistrationClientURI, accessToken); err != nil {
			s.logger.Error("failed to unregister OAuth client (continuing with deletion)", "error", err, "client_id", provider.ClientID)
		} else {
			s.logger.Info("OAuth client unregistered successfully", "client_id", provider.ClientID)
		}
	} else if provider.RegistrationMethod == OIDCRegistrationMethodManual {
		s.logger.Info("deleting manually registered OIDC provider (client must be cleaned up manually at IdP)", "client_id", provider.ClientID, "issuer_url", provider.IssuerURL)
	}

	return s.oidcProviderDB.DeleteOIDCProviderByID(ctx, providerID)
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(numBytes int) (string, error) {
	bytes := make([]byte, numBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// extractEmailDomain extracts the domain from an email address
// Assumes the email is already validated (contains @ symbol)
func extractEmailDomain(email string) string {
	// Find the @ symbol (searching from the end for efficiency)
	atIndex := -1
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			atIndex = i
			break
		}
	}

	return email[atIndex+1:]
}
