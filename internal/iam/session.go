package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/crypto/token"
	"github.com/travisbale/heimdall/internal/events"
)

// SessionTokens contains all tokens issued for a user session
type SessionTokens struct {
	AccessToken            string
	RefreshToken           string
	MFAChallengeToken      string
	MFASetupToken          string
	AccessExpiration       time.Duration
	RefreshExpiration      time.Duration
	MFAChallengeExpiration time.Duration
	MFASetupExpiration     time.Duration
}

// RequiresMFA returns true if MFA verification is needed to complete authentication
func (s *SessionTokens) RequiresMFA() bool {
	return s.MFAChallengeToken != ""
}

// RequiresMFASetup returns true if user must set up MFA before getting full access
func (s *SessionTokens) RequiresMFASetup() bool {
	return s.MFASetupToken != ""
}

// refreshTokenDB abstracts database operations for refresh tokens
type refreshTokenDB interface {
	Create(ctx context.Context, token *RefreshToken) (*RefreshToken, error)
	GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	GetByHashIncludingRevoked(ctx context.Context, tokenHash string) (*RefreshToken, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*RefreshToken, error)
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error
	RevokeByID(ctx context.Context, id uuid.UUID) error
	RevokeByHash(ctx context.Context, tokenHash string) error
	RevokeByFamilyID(ctx context.Context, familyID uuid.UUID) error
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}

// SessionService manages refresh token storage for session management
type SessionService struct {
	refreshTokenDB refreshTokenDB
	logger         logger
}

// SessionServiceConfig contains dependencies for SessionService
type SessionServiceConfig struct {
	RefreshTokenDB refreshTokenDB
	Logger         logger
}

// NewSessionService creates a new session service
func NewSessionService(config *SessionServiceConfig) *SessionService {
	return &SessionService{
		refreshTokenDB: config.RefreshTokenDB,
		logger:         config.Logger,
	}
}

// StoreSession stores a refresh token in the database
func (s *SessionService) StoreSession(ctx context.Context, rt *RefreshToken) error {
	_, err := s.refreshTokenDB.Create(ctx, rt)
	if err != nil {
		return fmt.Errorf("failed to store session: %w", err)
	}

	s.logger.InfoContext(ctx, "session stored", "user_id", rt.UserID, "user_agent", rt.UserAgent)
	return nil
}

// ValidateSession checks if a refresh token is valid (not revoked, not expired)
func (s *SessionService) ValidateSession(ctx context.Context, refreshToken string) (*RefreshToken, error) {
	tokenHash := token.Hash(refreshToken)

	storedToken, err := s.refreshTokenDB.GetByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	if err := s.refreshTokenDB.UpdateLastUsed(ctx, storedToken.ID); err != nil {
		s.logger.ErrorContext(ctx, "failed to update session last used", "error", err, "session_id", storedToken.ID)
		// Non-fatal: continue even if update fails
	}

	return storedToken, nil
}

// RotateSession validates a refresh token and revokes it for rotation.
// Returns the old token's metadata (including FamilyID) for creating the new token.
func (s *SessionService) RotateSession(ctx context.Context, refreshToken string) (*RefreshToken, error) {
	tokenHash := token.Hash(refreshToken)

	// Get token including revoked ones for reuse detection
	storedToken, err := s.refreshTokenDB.GetByHashIncludingRevoked(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	// REUSE DETECTION: If token already revoked, it's being replayed (theft)
	if storedToken.RevokedAt != nil {
		s.logger.WarnContext(ctx, events.TokenReuseDetected, "family_id", storedToken.FamilyID)

		// Revoke entire token family to invalidate attacker's tokens too
		if err := s.refreshTokenDB.RevokeByFamilyID(ctx, storedToken.FamilyID); err != nil {
			s.logger.ErrorContext(ctx, "failed to revoke token family", "error", err, "family_id", storedToken.FamilyID)
		}

		return nil, ErrTokenReused
	}

	// Revoke old token (rotation) - this makes it detectable if reused
	if err := s.refreshTokenDB.RevokeByHash(ctx, tokenHash); err != nil {
		s.logger.ErrorContext(ctx, "failed to revoke rotated token", "error", err)
		// Continue anyway - token validation already passed
	}

	return storedToken, nil
}

// ListSessions returns all active sessions for a user
func (s *SessionService) ListSessions(ctx context.Context, userID uuid.UUID) ([]*RefreshToken, error) {
	return s.refreshTokenDB.ListByUserID(ctx, userID)
}

// RevokeSession revokes a specific session by ID
func (s *SessionService) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	if err := s.refreshTokenDB.RevokeByID(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	s.logger.InfoContext(ctx, "session revoked", "session_id", sessionID)
	return nil
}

// RevokeSessionByToken revokes a session by the raw refresh token (for logout)
func (s *SessionService) RevokeSessionByToken(ctx context.Context, refreshToken string) error {
	tokenHash := token.Hash(refreshToken)

	if err := s.refreshTokenDB.RevokeByHash(ctx, tokenHash); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	s.logger.InfoContext(ctx, "session revoked by token")
	return nil
}

// RevokeAllSessions revokes all sessions for a user (sign out everywhere)
func (s *SessionService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	if err := s.refreshTokenDB.RevokeAllByUserID(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke all sessions: %w", err)
	}

	s.logger.InfoContext(ctx, "all sessions revoked", "user_id", userID)
	return nil
}

// DeleteExpiredSessions cleans up expired and old revoked tokens
func (s *SessionService) DeleteExpiredSessions(ctx context.Context) error {
	if err := s.refreshTokenDB.DeleteExpired(ctx); err != nil {
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	s.logger.InfoContext(ctx, "expired sessions deleted")
	return nil
}
