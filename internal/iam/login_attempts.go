package iam

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/events"
)

// Lockout thresholds - number of failed attempts before lockout kicks in
const (
	lockoutThreshold1 = 5
	lockoutThreshold2 = 10
	lockoutThreshold3 = 15
	lockoutThreshold4 = 20
)

// Lockout durations - how long the account is locked at each threshold
const (
	lockoutDuration1 = 5 * time.Minute
	lockoutDuration2 = 15 * time.Minute
	lockoutDuration3 = 1 * time.Hour
	lockoutDuration4 = 24 * time.Hour
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
	DB     loginAttemptsDB
	Logger *slog.Logger
}

// IsAccountLocked checks if an email is currently locked out and when the lock expires
func (s *LoginAttemptsService) IsAccountLocked(ctx context.Context, email string) (bool, time.Time, error) {
	lockedUntil, err := s.DB.GetMostRecentLockout(ctx, email)
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

	failedCount, err := s.DB.GetRecentFailedAttempts(ctx, email, windowStart)
	if err != nil {
		return fmt.Errorf("failed to get recent attempts: %w", err)
	}
	failedCount = failedCount + 1 // Include the current attempt

	// Progressive lockout: longer delays after repeated failures
	var lockedUntil *time.Time
	switch failedCount {
	case lockoutThreshold1:
		t := time.Now().Add(lockoutDuration1)
		lockedUntil = &t
	case lockoutThreshold2:
		t := time.Now().Add(lockoutDuration2)
		lockedUntil = &t
	case lockoutThreshold3:
		t := time.Now().Add(lockoutDuration3)
		lockedUntil = &t
	case lockoutThreshold4:
		t := time.Now().Add(lockoutDuration4)
		lockedUntil = &t
	}

	// Log account lockout events
	if lockedUntil != nil {
		s.Logger.InfoContext(ctx, events.AccountLocked, "email", email, "failed_count", failedCount, "locked_until", lockedUntil)
	}

	return s.DB.RecordAttempt(ctx, email, userID, lockedUntil)
}

// RecordSuccessfulLogin clears failed login attempts for the user
func (s *LoginAttemptsService) RecordSuccessfulLogin(ctx context.Context, userID uuid.UUID) error {
	err := s.DB.DeleteLoginAttempts(ctx, userID)
	if err != nil {
		s.Logger.ErrorContext(ctx, "failed to delete login attempts", "error", err)
	}

	return nil
}
