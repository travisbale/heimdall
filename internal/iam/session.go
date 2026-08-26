package iam

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/knowhere/crypto/token"
	"github.com/travisbale/knowhere/identity"
)

// SessionTokens contains all tokens for an authenticated session
type SessionTokens struct {
	AccessToken            string
	RefreshToken           string
	MFAChallengeToken      string
	MFASetupToken          string
	DeviceToken            string // Trusted device token (set when user opts to trust device after MFA)
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

type refreshTokenDB interface {
	Create(ctx context.Context, token *RefreshToken) (*RefreshToken, error)
	GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	GetByHashIncludingRevoked(ctx context.Context, tokenHash string) (*RefreshToken, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*RefreshToken, error)
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error
	RevokeByID(ctx context.Context, id uuid.UUID) error
	RevokeByHash(ctx context.Context, tokenHash string) error
	RevokeByFamilyID(ctx context.Context, familyID uuid.UUID) error
	CountLiveInFamily(ctx context.Context, familyID uuid.UUID) (int64, error)
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}

const rotationGrace = 10 * time.Second

// SessionService manages refresh token storage for session management
type SessionService struct {
	RefreshTokenDB refreshTokenDB
	Logger         *slog.Logger
}

// StoreSession stores a refresh token in the database
func (s *SessionService) StoreSession(ctx context.Context, rt *RefreshToken) error {
	_, err := s.RefreshTokenDB.Create(ctx, rt)
	if err != nil {
		return fmt.Errorf("failed to store session: %w", err)
	}

	s.Logger.InfoContext(ctx, events.SessionCreated, "user_id", rt.UserID, "user_agent", rt.UserAgent)
	return nil
}

// ValidateSession checks if a refresh token is valid (not revoked, not expired)
func (s *SessionService) ValidateSession(ctx context.Context, refreshToken string) (*RefreshToken, error) {
	tokenHash := token.Hash(refreshToken)

	storedToken, err := s.RefreshTokenDB.GetByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	if err := s.RefreshTokenDB.UpdateLastUsed(ctx, storedToken.ID); err != nil {
		s.Logger.ErrorContext(ctx, "failed to update session last used", "error", err, "session_id", storedToken.ID)
		// Non-fatal: continue even if update fails
	}

	return storedToken, nil
}

// RotateSession validates a refresh token and revokes it for rotation.
// Returns the old token's metadata (including FamilyID) for creating the new token.
func (s *SessionService) RotateSession(ctx context.Context, refreshToken string) (*RefreshToken, error) {
	tokenHash := token.Hash(refreshToken)

	// Get token including revoked ones for reuse detection
	storedToken, err := s.RefreshTokenDB.GetByHashIncludingRevoked(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	// A spent token is either a client repeating itself or somebody else holding a copy.
	if storedToken.RevokedAt != nil {
		if s.retriedRotation(ctx, storedToken) {
			s.Logger.InfoContext(ctx, events.RotationRetried, "family_id", storedToken.FamilyID)
			return storedToken, nil
		}

		s.Logger.WarnContext(ctx, events.TokenReuseDetected, "family_id", storedToken.FamilyID)

		// Revoke entire token family to invalidate attacker's tokens too
		if err := s.RefreshTokenDB.RevokeByFamilyID(ctx, storedToken.FamilyID); err != nil {
			s.Logger.ErrorContext(ctx, "failed to revoke token family", "error", err, "family_id", storedToken.FamilyID)
		}

		return nil, ErrTokenReused
	}

	// Revoke old token (rotation) - this makes it detectable if reused
	if err := s.RefreshTokenDB.RevokeByHash(ctx, tokenHash); err != nil {
		s.Logger.ErrorContext(ctx, "failed to revoke rotated token", "error", err)
		// Continue anyway - token validation already passed
	}

	return storedToken, nil
}

// retriedRotation reports whether a spent token is a client retrying rather than an attacker replaying
func (s *SessionService) retriedRotation(ctx context.Context, t *RefreshToken) bool {
	if t.RevokedAt == nil || time.Since(*t.RevokedAt) > rotationGrace {
		return false
	}

	// The client that spent the token is the only one with a reason to present it again
	if agent := identity.GetUserAgent(ctx); agent == "" || agent != t.UserAgent {
		return false
	}

	live, err := s.RefreshTokenDB.CountLiveInFamily(ctx, t.FamilyID)
	if err != nil {
		s.Logger.ErrorContext(ctx, "failed to count live tokens in family", "error", err, "family_id", t.FamilyID)
		return false
	}

	return live > 0
}

// ListSessions returns all active sessions for a user
func (s *SessionService) ListSessions(ctx context.Context, userID uuid.UUID) ([]*RefreshToken, error) {
	return s.RefreshTokenDB.ListByUserID(ctx, userID)
}

// RevokeSession revokes a specific session by ID
func (s *SessionService) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	if err := s.RefreshTokenDB.RevokeByID(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	s.Logger.InfoContext(ctx, events.SessionRevoked, "session_id", sessionID)
	return nil
}

// RevokeSessionByToken revokes a session by the raw refresh token (for logout)
func (s *SessionService) RevokeSessionByToken(ctx context.Context, refreshToken string) error {
	tokenHash := token.Hash(refreshToken)

	if err := s.RefreshTokenDB.RevokeByHash(ctx, tokenHash); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	s.Logger.InfoContext(ctx, events.SessionRevoked)
	return nil
}

// RevokeAllSessions revokes all sessions for a user (sign out everywhere)
func (s *SessionService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	if err := s.RefreshTokenDB.RevokeAllByUserID(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke all sessions: %w", err)
	}

	s.Logger.InfoContext(ctx, events.AllSessionsRevoked, "user_id", userID)
	return nil
}

// DeleteExpiredSessions cleans up expired and old revoked tokens
func (s *SessionService) DeleteExpiredSessions(ctx context.Context) error {
	if err := s.RefreshTokenDB.DeleteExpired(ctx); err != nil {
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	s.Logger.InfoContext(ctx, events.ExpiredSessionsDeleted)
	return nil
}
