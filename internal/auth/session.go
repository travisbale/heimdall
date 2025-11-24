package auth

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
	RequiresMFA            bool
}

type jwtService interface {
	IssueAccessToken(tenantID, userID uuid.UUID, scopes []sdk.Scope) (string, error)
	IssueMFAChallengeToken(tenantID, userID uuid.UUID) (string, error)
	IssueRefreshToken(tenantID, userID uuid.UUID) (string, error)
	ValidateToken(token string) (*jwt.Claims, error)
	GetAccessTokenExpiration() time.Duration
	GetRefreshTokenExpiration() time.Duration
	GetMFAChallengeTokenExpiration() time.Duration
}

// SessionService handles session token creation for authenticated users
type SessionService struct {
	mfaService  mfaService
	rbacService rbacService
	jwtService  jwtService
	logger      logger
}

type mfaService interface {
	GetStatus(ctx context.Context, userID uuid.UUID) (*MFAStatus, error)
}

// SessionServiceConfig contains dependencies for SessionService
type SessionServiceConfig struct {
	MFAService  mfaService
	RBACService rbacService
	JWTIssuer   jwtService
	Logger      logger
}

// NewSessionService creates a new SessionService
func NewSessionService(config *SessionServiceConfig) *SessionService {
	return &SessionService{
		mfaService:  config.MFAService,
		rbacService: config.RBACService,
		jwtService:  config.JWTIssuer,
		logger:      config.Logger,
	}
}

// CreateSession generates tokens for an authenticated user session
func (s *SessionService) CreateSession(ctx context.Context, tenantID, userID uuid.UUID, checkMFA bool) (*SessionTokens, error) {
	tokens := &SessionTokens{
		AccessExpiration:       s.jwtService.GetAccessTokenExpiration(),
		RefreshExpiration:      s.jwtService.GetRefreshTokenExpiration(),
		MFAChallengeExpiration: s.jwtService.GetMFAChallengeTokenExpiration(),
	}

	// Check if MFA verification required
	if checkMFA {
		mfaStatus, err := s.mfaService.GetStatus(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to get MFA status: %w", err)
		}

		// User requires MFA - issue challenge token only
		if mfaStatus.VerifiedAt != nil {
			challengeToken, err := s.jwtService.IssueMFAChallengeToken(tenantID, userID)
			if err != nil {
				return nil, fmt.Errorf("failed to generate MFA challenge token: %w", err)
			}

			tokens.MFAChallengeToken = challengeToken
			tokens.RequiresMFA = true
			return tokens, nil
		}
	}

	// User is fully authenticated - issue access and refresh tokens
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

	tokens.AccessToken = accessToken
	tokens.RefreshToken = refreshToken
	tokens.RequiresMFA = false

	return tokens, nil
}

// RefreshSession validates a refresh token and generates new session tokens
func (s *SessionService) RefreshSession(ctx context.Context, refreshToken string) (*SessionTokens, error) {
	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired refresh token: %w", err)
	}

	scopes, err := s.rbacService.GetUserScopes(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user scopes: %w", err)
	}

	accessToken, err := s.jwtService.IssueAccessToken(claims.TenantID, claims.UserID, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := s.jwtService.IssueRefreshToken(claims.TenantID, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &SessionTokens{
		AccessToken:       accessToken,
		RefreshToken:      newRefreshToken,
		AccessExpiration:  s.jwtService.GetAccessTokenExpiration(),
		RefreshExpiration: s.jwtService.GetRefreshTokenExpiration(),
		RequiresMFA:       false,
	}, nil
}
