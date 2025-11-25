package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

// SessionTokens contains all tokens issued for a user session
type SessionTokens struct {
	AccessToken            string
	RefreshToken           string
	MFAChallengeToken      string
	AccessExpiration       time.Duration
	RefreshExpiration      time.Duration
	MFAChallengeExpiration time.Duration
}

// RequiresMFA returns true if MFA verification is needed to complete authentication
func (s *SessionTokens) RequiresMFA() bool {
	return s.MFAChallengeToken != ""
}

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
}

type jwtService interface {
	IssueAccessToken(tenantID, userID uuid.UUID, scopes []sdk.Scope) (string, error)
	IssueMFAChallengeToken(tenantID, userID uuid.UUID) (string, error)
	IssueRefreshToken(tenantID, userID uuid.UUID) (string, error)
	ValidateMFAChallengeToken(token string) (*jwt.Claims, error)
	ValidateToken(token string) (*jwt.Claims, error)
	GetAccessTokenExpiration() time.Duration
	GetRefreshTokenExpiration() time.Duration
	GetMFAChallengeTokenExpiration() time.Duration
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

	mfaEnabled, err := s.mfaService.IsMFAEnabled(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check MFA status: %w", err)
	}

	if mfaEnabled {
		return s.issueMFAChallenge(user.TenantID, user.ID)
	}

	return s.createSession(ctx, user.TenantID, user.ID)
}

// AuthenticateWithOIDC handles OAuth/OIDC callback
func (s *AuthService) AuthenticateWithOIDC(ctx context.Context, state, code string) (*SessionTokens, error) {
	user, err := s.oidcService.ProcessCallback(ctx, state, code)
	if err != nil {
		return nil, err
	}

	// No MFA check - OIDC providers handle their own MFA
	return s.createSession(ctx, user.TenantID, user.ID)
}

// CompleteRegistration handles email verification and auto-login
func (s *AuthService) CompleteRegistration(ctx context.Context, token, password string) (*SessionTokens, error) {
	user, err := s.userService.VerifyEmailAndSetPassword(ctx, token, password)
	if err != nil {
		return nil, err
	}

	mfaEnabled, err := s.mfaService.IsMFAEnabled(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check MFA status: %w", err)
	}

	if mfaEnabled {
		return s.issueMFAChallenge(user.TenantID, user.ID)
	}

	return s.createSession(ctx, user.TenantID, user.ID)
}

// AuthenticateWithMFA completes MFA challenge and issues final tokens
func (s *AuthService) AuthenticateWithMFA(ctx context.Context, challengeToken, code string) (*SessionTokens, error) {
	claims, err := s.jwtService.ValidateMFAChallengeToken(challengeToken)
	if err != nil {
		return nil, ErrInvalidChallengeToken
	}

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

	return s.createSession(ctx, claims.TenantID, claims.UserID)
}

// issueMFAChallenge creates a challenge token for MFA verification
func (s *AuthService) issueMFAChallenge(tenantID, userID uuid.UUID) (*SessionTokens, error) {
	challengeToken, err := s.jwtService.IssueMFAChallengeToken(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate MFA challenge token: %w", err)
	}

	return &SessionTokens{
		MFAChallengeToken:      challengeToken,
		MFAChallengeExpiration: s.jwtService.GetMFAChallengeTokenExpiration(),
	}, nil
}

// createSession issues access and refresh tokens for a fully authenticated user
func (s *AuthService) createSession(ctx context.Context, tenantID, userID uuid.UUID) (*SessionTokens, error) {
	scopes, err := s.rbacService.GetUserScopes(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user scopes: %w", err)
	}

	accessToken, err := s.jwtService.IssueAccessToken(tenantID, userID, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.jwtService.IssueRefreshToken(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &SessionTokens{
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		AccessExpiration:  s.jwtService.GetAccessTokenExpiration(),
		RefreshExpiration: s.jwtService.GetRefreshTokenExpiration(),
	}, nil
}
