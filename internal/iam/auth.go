package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

type passwordService interface {
	VerifyCredentials(ctx context.Context, email, password string) (*User, error)
}

type oidcAuthService interface {
	ProcessCallback(ctx context.Context, state, code string) (*User, error)
}

type userAccountService interface {
	VerifyEmailAndSetPassword(ctx context.Context, tokenStr, password string) (*User, error)
}

type mfaVerificationService interface {
	IsMFAEnabled(ctx context.Context, userID uuid.UUID) (bool, error)
	VerifyCode(ctx context.Context, userID uuid.UUID, code string) error
	SetupMFA(ctx context.Context, userID uuid.UUID) (*MFAEnrollment, error)
	EnableMFA(ctx context.Context, userID uuid.UUID, code string) error
}

type jwtService interface {
	IssueAccessToken(tenantID, userID uuid.UUID, scopes []sdk.Scope) (string, time.Duration, error)
	IssueMFAChallengeToken(tenantID, userID uuid.UUID) (string, time.Duration, error)
	IssueMFASetupToken(tenantID, userID uuid.UUID) (string, time.Duration, error)
	IssueRefreshToken(tenantID, userID uuid.UUID) (string, time.Duration, error)
	ValidateMFAChallengeToken(token string) (*jwt.Claims, error)
	ValidateMFASetupToken(token string) (*jwt.Claims, error)
	ValidateToken(token string) (*jwt.Claims, error)
}

// AuthService orchestrates authentication flows
type AuthService struct {
	passwordService passwordService
	oidcService     oidcAuthService
	userService     userAccountService
	mfaService      mfaVerificationService
	rbacService     rbacService
	jwtService      jwtService
	logger          logger
}

// AuthServiceConfig contains dependencies for AuthService
type AuthServiceConfig struct {
	PasswordService passwordService
	OIDCService     oidcAuthService
	UserService     userAccountService
	MFAService      mfaVerificationService
	RBACService     rbacService
	JWTService      jwtService
	Logger          logger
}

// NewAuthService creates a new AuthService
func NewAuthService(config *AuthServiceConfig) *AuthService {
	return &AuthService{
		passwordService: config.PasswordService,
		oidcService:     config.OIDCService,
		userService:     config.UserService,
		mfaService:      config.MFAService,
		rbacService:     config.RBACService,
		jwtService:      config.JWTService,
		logger:          config.Logger,
	}
}

// AuthenticateWithPassword handles password-based authentication
func (s *AuthService) AuthenticateWithPassword(ctx context.Context, email, password string) (*SessionTokens, error) {
	user, err := s.passwordService.VerifyCredentials(ctx, email, password)
	if err != nil {
		return nil, err
	}

	return s.completeAuthentication(ctx, user)
}

// AuthenticateWithOIDC handles OAuth/OIDC callback
func (s *AuthService) AuthenticateWithOIDC(ctx context.Context, state, code string) (*SessionTokens, error) {
	user, err := s.oidcService.ProcessCallback(ctx, state, code)
	if err != nil {
		return nil, err
	}

	return s.completeAuthentication(ctx, user)
}

// CompleteRegistration handles email verification and auto-login
func (s *AuthService) CompleteRegistration(ctx context.Context, token, password string) (*SessionTokens, error) {
	user, err := s.userService.VerifyEmailAndSetPassword(ctx, token, password)
	if err != nil {
		return nil, err
	}

	return s.completeAuthentication(ctx, user)
}

// AuthenticateWithMFA completes MFA challenge and issues final tokens
func (s *AuthService) AuthenticateWithMFA(ctx context.Context, challengeToken, code string) (*SessionTokens, error) {
	claims, err := s.jwtService.ValidateMFAChallengeToken(challengeToken)
	if err != nil {
		return nil, ErrInvalidChallengeToken
	}

	// Set tenant context from token for RLS-protected operations
	ctx = identity.WithTenant(ctx, claims.TenantID)

	if err := s.mfaService.VerifyCode(ctx, claims.UserID, code); err != nil {
		return nil, err
	}

	return s.createSession(ctx, claims.TenantID, claims.UserID)
}

// RefreshSession validates a refresh token and generates new session tokens
func (s *AuthService) RefreshSession(ctx context.Context, refreshToken string) (*SessionTokens, error) {
	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired refresh token: %w", err)
	}

	// Set tenant context from token for RLS-protected operations
	ctx = identity.WithTenant(ctx, claims.TenantID)

	return s.createSession(ctx, claims.TenantID, claims.UserID)
}

// SetupRequiredMFA validates the setup token and initiates MFA enrollment
func (s *AuthService) SetupRequiredMFA(ctx context.Context, setupToken string) (*MFAEnrollment, error) {
	claims, err := s.jwtService.ValidateMFASetupToken(setupToken)
	if err != nil {
		return nil, ErrInvalidSetupToken
	}

	// Set tenant context from token for RLS-protected operations
	ctx = identity.WithTenant(ctx, claims.TenantID)

	return s.mfaService.SetupMFA(ctx, claims.UserID)
}

// EnableRequiredMFA validates the setup token, enables MFA, and returns a challenge token
func (s *AuthService) EnableRequiredMFA(ctx context.Context, setupToken, code string) (*SessionTokens, error) {
	claims, err := s.jwtService.ValidateMFASetupToken(setupToken)
	if err != nil {
		return nil, ErrInvalidSetupToken
	}

	// Set tenant context from token for RLS-protected operations
	ctx = identity.WithTenant(ctx, claims.TenantID)

	if err := s.mfaService.EnableMFA(ctx, claims.UserID, code); err != nil {
		return nil, err
	}

	s.logger.Info(ctx, events.MFAEnabled, "user_id", claims.UserID, "required", true)

	return s.issueMFAChallenge(claims.TenantID, claims.UserID)
}

// issueMFAChallenge creates a challenge token for MFA verification
func (s *AuthService) issueMFAChallenge(tenantID, userID uuid.UUID) (*SessionTokens, error) {
	challengeToken, expiration, err := s.jwtService.IssueMFAChallengeToken(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate MFA challenge token: %w", err)
	}

	return &SessionTokens{
		MFAChallengeToken:      challengeToken,
		MFAChallengeExpiration: expiration,
	}, nil
}

// issueMFASetupChallenge creates a setup token for required MFA configuration
func (s *AuthService) issueMFASetupChallenge(tenantID, userID uuid.UUID) (*SessionTokens, error) {
	setupToken, expiration, err := s.jwtService.IssueMFASetupToken(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate MFA setup token: %w", err)
	}

	return &SessionTokens{
		MFASetupToken:      setupToken,
		MFASetupExpiration: expiration,
	}, nil
}

// completeAuthentication checks MFA status and either issues tokens or requires MFA
func (s *AuthService) completeAuthentication(ctx context.Context, user *User) (*SessionTokens, error) {
	// Set tenant context for RLS-protected operations (MFA check, role check, scopes)
	ctx = identity.WithTenant(ctx, user.TenantID)

	mfaEnabled, err := s.mfaService.IsMFAEnabled(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check MFA status: %w", err)
	}

	if mfaEnabled {
		return s.issueMFAChallenge(user.TenantID, user.ID)
	}

	// Check if role requires MFA but user hasn't set it up
	rolesRequireMFA, err := s.rbacService.UserRolesRequireMFA(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check MFA requirements: %w", err)
	}

	if rolesRequireMFA {
		s.logger.Info(ctx, events.MFASetupRequired, "user_id", user.ID)
		return s.issueMFASetupChallenge(user.TenantID, user.ID)
	}

	return s.createSession(ctx, user.TenantID, user.ID)
}

// createSession issues access and refresh tokens for a fully authenticated user
func (s *AuthService) createSession(ctx context.Context, tenantID, userID uuid.UUID) (*SessionTokens, error) {
	scopes, err := s.rbacService.GetUserScopes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user scopes: %w", err)
	}

	accessToken, accessExpiration, err := s.jwtService.IssueAccessToken(tenantID, userID, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, refreshExpiration, err := s.jwtService.IssueRefreshToken(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &SessionTokens{
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		AccessExpiration:  accessExpiration,
		RefreshExpiration: refreshExpiration,
	}, nil
}
