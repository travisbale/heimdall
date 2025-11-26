package iam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/crypto/token"
	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/heimdall/sdk"
)

// oidcProviderLookup defines the provider lookup methods needed by OIDCAuthService
type oidcProviderLookup interface {
	GetOIDCProvider(ctx context.Context, providerID uuid.UUID) (*OIDCProviderConfig, error)
	GetOIDCProvidersByDomain(ctx context.Context, domain string) ([]*OIDCProviderConfig, error)
}

// OIDCAuthServiceConfig holds the dependencies for creating an OIDCAuthService
type OIDCAuthServiceConfig struct {
	OIDCProviderService oidcProviderLookup
	OIDCLinkDB          oidcLinkDB
	OIDCSessionDB       oidcSessionDB
	UserDB              userDB
	TenantsDB           tenantsDB
	SystemProviders     map[sdk.OIDCProviderType]OIDCProvider
	ProviderFactory     oidcProviderFactory
	PublicURL           string
	Logger              logger
}

// OIDCAuthService handles OAuth/SSO authentication flows
type OIDCAuthService struct {
	oidcProviderService oidcProviderLookup
	oidcLinkDB          oidcLinkDB
	oidcSessionDB       oidcSessionDB
	userDB              userDB
	tenantsDB           tenantsDB
	systemProviders     map[sdk.OIDCProviderType]OIDCProvider
	providerFactory     oidcProviderFactory
	publicURL           string
	logger              logger
}

// NewOIDCAuthService creates a new OIDCAuthService
func NewOIDCAuthService(config *OIDCAuthServiceConfig) *OIDCAuthService {
	return &OIDCAuthService{
		oidcProviderService: config.OIDCProviderService,
		oidcLinkDB:          config.OIDCLinkDB,
		oidcSessionDB:       config.OIDCSessionDB,
		userDB:              config.UserDB,
		tenantsDB:           config.TenantsDB,
		systemProviders:     config.SystemProviders,
		providerFactory:     config.ProviderFactory,
		publicURL:           config.PublicURL,
		logger:              config.Logger,
	}
}

// getCallbackURL returns the full OAuth callback URL
func (s *OIDCAuthService) getCallbackURL() string {
	return s.publicURL + sdk.RouteV1OAuthCallback
}

// StartSSOLogin initiates an OIDC login flow for corporate SSO (domain-based discovery)
func (s *OIDCAuthService) StartSSOLogin(ctx context.Context, email string) (string, error) {
	domain, err := extractEmailDomain(email)
	if err != nil {
		return "", fmt.Errorf("invalid email format: %w", err)
	}

	providerConfigs, err := s.oidcProviderService.GetOIDCProvidersByDomain(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("failed to lookup SSO provider: %w", err)
	}

	if len(providerConfigs) == 0 {
		return "", ErrSSONotConfigured
	}

	// Use the first enabled provider config
	providerConfig := providerConfigs[0]

	provider, err := s.providerFactory.NewProvider(
		ctx,
		providerConfig.IssuerURL,
		providerConfig.ClientID,
		providerConfig.ClientSecret,
		providerConfig.Scopes,
	)
	if err != nil {
		return "", fmt.Errorf("failed to initialize SSO provider: %w", err)
	}

	// Generate CSRF state token (32 bytes, base64 encoded)
	state, err := token.Generate(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state token: %w", err)
	}

	// Generate PKCE code verifier (32 bytes, base64 encoded)
	codeVerifier, err := token.Generate(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Create OIDC session for SSO login
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   codeVerifier,
		OIDCProviderID: &providerConfig.ID, // Corporate SSO - reference provider config
		ProviderType:   nil,                // Not a system-wide provider
		RedirectURI:    s.getCallbackURL(),
		TenantID:       &providerConfig.TenantID, // Corporate SSO - store tenant ID
		ExpiresAt:      time.Now().Add(oidcSessionExpiration),
	}

	_, err = s.oidcSessionDB.CreateOIDCSession(ctx, session)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC session: %w", err)
	}

	// Use scopes from provider configuration
	authURL, err := provider.GetAuthorizationURL(state, codeVerifier, session.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization URL: %w", err)
	}

	return authURL, nil
}

// StartOIDCLogin initiates an OIDC login flow for individual OAuth registration
func (s *OIDCAuthService) StartOIDCLogin(ctx context.Context, providerType sdk.OIDCProviderType) (string, error) {
	// Use system-wide provider for individual OAuth registration
	oidcProvider, ok := s.systemProviders[providerType]
	if !ok {
		return "", ErrOIDCProviderNotConfigured
	}

	// Generate CSRF state token
	state, err := token.Generate(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state token: %w", err)
	}

	// Generate PKCE code verifier
	codeVerifier, err := token.Generate(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Create OIDC session for individual OAuth login
	session := &OIDCSession{
		State:          state,
		CodeVerifier:   codeVerifier,
		OIDCProviderID: nil,           // Not a tenant-specific provider
		ProviderType:   &providerType, // System-wide provider (Google, GitHub, etc.)
		RedirectURI:    s.getCallbackURL(),
		TenantID:       nil, // Tenant determined during callback
		ExpiresAt:      time.Now().Add(oidcSessionExpiration),
	}

	_, err = s.oidcSessionDB.CreateOIDCSession(ctx, session)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC session: %w", err)
	}

	authURL, err := oidcProvider.GetAuthorizationURL(state, codeVerifier, session.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization URL: %w", err)
	}

	return authURL, nil
}

// ProcessCallback processes the OAuth callback and authenticates the user
func (s *OIDCAuthService) ProcessCallback(ctx context.Context, state, code string) (*User, error) {
	// Get the OIDC session by state
	session, err := s.oidcSessionDB.GetOIDCSessionByState(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired state: %w", err)
	}

	// Clean up the OIDC session after callback completes
	defer func() {
		if err := s.oidcSessionDB.DeleteOIDCSession(ctx, session.ID); err != nil {
			s.logger.ErrorContext(ctx, "failed to delete OIDC session", "error", err)
		}
	}()

	var user *User

	// Route to appropriate handler based on session type
	if session.OIDCProviderID != nil {
		user, _, err = s.handleSSOCallback(ctx, session, code)
		if err != nil {
			s.logger.InfoContext(ctx, events.SSOLoginFailed, "error", err.Error(), "provider_id", *session.OIDCProviderID)
			return nil, err
		}
	} else if session.ProviderType != nil {
		user, err = s.handleIndividualOAuthCallback(ctx, session, code)
		if err != nil {
			s.logger.InfoContext(ctx, events.OAuthLoginFailed, "error", err.Error(), "provider_type", *session.ProviderType)
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("session has neither OIDCProviderID nor ProviderType")
	}

	return user, nil
}

// handleSSOCallback processes corporate SSO callbacks
func (s *OIDCAuthService) handleSSOCallback(ctx context.Context, session *OIDCSession, code string) (*User, *OIDCLink, error) {
	// Get tenant-specific provider configuration
	providerConfig, err := s.oidcProviderService.GetOIDCProvider(ctx, *session.OIDCProviderID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get tenant OIDC provider: %w", err)
	}

	// Create provider instance
	oidcProvider, err := s.providerFactory.NewProvider(
		ctx,
		providerConfig.IssuerURL,
		providerConfig.ClientID,
		providerConfig.ClientSecret,
		providerConfig.Scopes,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create tenant provider: %w", err)
	}

	// Exchange authorization code for tokens
	tokenResponse, err := oidcProvider.ExchangeCode(ctx, code, session.CodeVerifier, session.RedirectURI)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	// Get user info from the provider
	userInfo, err := oidcProvider.GetUserInfo(ctx, tokenResponse.AccessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Check if this provider account is already linked
	existingLink, err := s.oidcLinkDB.GetOIDCLinkByProvider(ctx, *session.OIDCProviderID, userInfo.Sub)
	if err != nil && err != ErrOIDCLinkNotFound {
		return nil, nil, fmt.Errorf("failed to check existing OIDC link: %w", err)
	}

	// Handle existing user login
	if existingLink != nil {
		return s.handleExistingSSOUser(ctx, existingLink)
	}

	return s.autoProvisionSSOUser(ctx, providerConfig, oidcProvider, tokenResponse.IDToken, userInfo)
}

// handleExistingSSOUser processes login for users with existing SSO links
func (s *OIDCAuthService) handleExistingSSOUser(ctx context.Context, link *OIDCLink) (*User, *OIDCLink, error) {
	if err := s.oidcLinkDB.UpdateOIDCLinkLastUsed(ctx, link.ID); err != nil {
		s.logger.ErrorContext(ctx, "failed to update OIDC link last used", "error", err)
	}

	// Get user by link's UserID to support email changes at provider
	user, err := s.userDB.GetUser(ctx, link.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user: %w", err)
	}

	s.logger.InfoContext(ctx, events.SSOLoginSucceeded, "user_id", user.ID, "email", user.Email, "provider_id", link.OIDCProviderID)

	return user, link, nil
}

// autoProvisionSSOUser creates or links a user account during SSO login
func (s *OIDCAuthService) autoProvisionSSOUser(ctx context.Context, providerConfig *OIDCProviderConfig, oidcProvider OIDCProvider, idToken string, userInfo *OIDCUserInfo) (*User, *OIDCLink, error) {
	if !providerConfig.AutoCreateUsers {
		return nil, nil, ErrAutoProvisioningDisabled
	}

	if providerConfig.RequireEmailVerification {
		if err := s.verifyEmailVerified(ctx, oidcProvider, idToken, userInfo); err != nil {
			return nil, nil, err
		}
	}

	existingUser, err := s.userDB.GetUserByEmail(ctx, userInfo.Email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	if existingUser != nil {
		// Email exists but provider sub is different → likely email reassignment
		// Require admin to manually deactivate old account before new employee can login
		s.logger.ErrorContext(ctx, "SSO login blocked: email exists with different provider sub",
			"email", userInfo.Email,
			"existing_user_id", existingUser.ID,
			"existing_status", existingUser.Status,
			"new_provider_sub", userInfo.Sub,
			"provider_id", providerConfig.ID)

		return nil, nil, ErrEmailConflict
	}

	user := &User{
		TenantID: providerConfig.TenantID,
		Email:    userInfo.Email,
		Status:   UserStatusActive,
	}

	user, err = s.userDB.CreateUser(ctx, user)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create user: %w", err)
	}

	link := &OIDCLink{
		UserID:           user.ID,
		OIDCProviderID:   providerConfig.ID,
		ProviderUserID:   userInfo.Sub,
		ProviderEmail:    userInfo.Email,
		ProviderMetadata: userInfo.Metadata,
	}

	link, err = s.oidcLinkDB.CreateOIDCLink(ctx, link)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OIDC link: %w", err)
	}

	return user, link, nil
}

// handleIndividualOAuthCallback processes individual OAuth callbacks
func (s *OIDCAuthService) handleIndividualOAuthCallback(ctx context.Context, session *OIDCSession, code string) (*User, error) {
	// Get system-wide provider
	oidcProvider, ok := s.systemProviders[*session.ProviderType]
	if !ok {
		return nil, fmt.Errorf("OIDC provider not configured: %s", *session.ProviderType)
	}

	// Exchange authorization code for tokens
	tokenResponse, err := oidcProvider.ExchangeCode(ctx, code, session.CodeVerifier, session.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	// Get user info from the provider
	userInfo, err := oidcProvider.GetUserInfo(ctx, tokenResponse.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Check if user already exists by email
	existingUser, err := s.userDB.GetUserByEmail(ctx, userInfo.Email)
	if err != nil && err != ErrUserNotFound {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	// Handle existing user login
	if existingUser != nil {
		s.logger.InfoContext(ctx, events.OAuthLoginSucceeded, "user_id", existingUser.ID, "email", existingUser.Email, "provider_type", *session.ProviderType)
		return existingUser, nil
	}

	// Verify email is verified by the provider
	if err := s.verifyEmailVerified(ctx, oidcProvider, tokenResponse.IDToken, userInfo); err != nil {
		return nil, err
	}

	// Bootstrap new tenant with user and System Admin role
	tenant, user, err := s.tenantsDB.BootstrapTenant(ctx, userInfo.Email, UserStatusActive)
	if err != nil {
		return nil, fmt.Errorf("failed to bootstrap tenant: %w", err)
	}

	s.logger.InfoContext(ctx, events.TenantCreated, "user_id", user.ID, "tenant_id", tenant.ID, "email", userInfo.Email)

	return user, nil
}

// verifyEmailVerified checks that the user's email is verified by the provider
func (s *OIDCAuthService) verifyEmailVerified(ctx context.Context, provider OIDCProvider, idToken string, userInfo *OIDCUserInfo) error {
	var emailVerified bool

	// Try to get email verification status from ID token if available
	if idToken != "" {
		// Note: Not all providers support ID tokens (e.g., GitHub uses OAuth 2.0, not OIDC)
		if claims, err := provider.ValidateIDToken(ctx, idToken); err == nil {
			emailVerified = claims.EmailVerified
		}
	}

	// Fall back to email verification status from userInfo endpoint if not already verified
	if !emailVerified {
		emailVerified = userInfo.EmailVerified
	}

	if !emailVerified {
		return ErrProviderEmailNotVerified
	}

	return nil
}
