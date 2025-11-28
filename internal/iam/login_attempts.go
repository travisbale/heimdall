package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/events"
)

const (
	lockoutDuration1 = 5 * time.Minute  // 5 failed attempts
	lockoutDuration2 = 15 * time.Minute // 10 failed attempts
	lockoutDuration3 = 1 * time.Hour    // 15 failed attempts
	lockoutDuration4 = 24 * time.Hour   // 20 failed attempts
)

// loginAttemptsDB defines the data access interface for login attempts
type loginAttemptsDB interface {
	RecordAttempt(ctx context.Context, email string, userID *uuid.UUID, lockedUntil *time.Time) error
	GetRecentFailedAttempts(ctx context.Context, email string, since time.Time) (int64, error)
	GetMostRecentLockout(ctx context.Context, email string) (*time.Time, error)
	DeleteLoginAttempts(ctx context.Context, userID uuid.UUID) error
}

// LoginAttemptsService handles login attempt tracking and account lockout logic
type LoginAttemptsService struct {
	db     loginAttemptsDB
	logger logger
}

// NewLoginAttemptsService creates a new login attempts service
func NewLoginAttemptsService(db loginAttemptsDB, logger logger) *LoginAttemptsService {
	return &LoginAttemptsService{
		db:     db,
		logger: logger,
	}
}

// IsAccountLocked checks if an email is currently locked out and when the lock expires
func (s *LoginAttemptsService) IsAccountLocked(ctx context.Context, email string) (bool, time.Time, error) {
	lockedUntil, err := s.db.GetMostRecentLockout(ctx, email)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("failed to get recent lockout: %w", err)
	}

	// If no lockout exists or lockout has expired, account is not locked
	if lockedUntil == nil || time.Now().After(*lockedUntil) {
		return false, time.Time{}, nil
	}

	// Account is locked
	return true, *lockedUntil, nil
}

// RecordFailedLogin records a failed login attempt and calculates the appropriate lockout expiry
func (s *LoginAttemptsService) RecordFailedLogin(ctx context.Context, email string, userID *uuid.UUID, lastLoginAt *time.Time) error {
	// Count failures since last successful login (or past 24 hours if never logged in)
	windowStart := time.Now().Add(-lockoutDuration4)
	if lastLoginAt != nil && lastLoginAt.After(windowStart) {
		windowStart = *lastLoginAt
	}

	failedCount, err := s.db.GetRecentFailedAttempts(ctx, email, windowStart)
	if err != nil {
		return fmt.Errorf("failed to get recent attempts: %w", err)
	}
	failedCount = failedCount + 1 // Include the current attempt

	// Progressive lockout: longer delays after repeated failures
	var lockedUntil *time.Time
	switch failedCount {
	case 5:
		t := time.Now().Add(lockoutDuration1)
		lockedUntil = &t
	case 10:
		t := time.Now().Add(lockoutDuration2)
		lockedUntil = &t
	case 15:
		t := time.Now().Add(lockoutDuration3)
		lockedUntil = &t
	case 20:
		t := time.Now().Add(lockoutDuration4)
		lockedUntil = &t
	default:
		lockedUntil = nil // Not a threshold - no lockout
	}

	// Log account lockout events
	if lockedUntil != nil {
		s.logger.InfoContext(ctx, events.AccountLocked, "email", email, "failed_count", failedCount, "locked_until", lockedUntil)
	}

	return s.db.RecordAttempt(ctx, email, userID, lockedUntil)
}

// RecordSuccessfulLogin clears failed login attempts for the user
func (s *LoginAttemptsService) RecordSuccessfulLogin(ctx context.Context, userID uuid.UUID) error {
	err := s.db.DeleteLoginAttempts(ctx, userID)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to delete login attempts", "error", err)
	}

	return nil
}
