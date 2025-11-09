package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
)

// LoginAttemptsDB handles database operations for login attempts
type LoginAttemptsDB struct {
	db *DB
}

// NewLoginAttemptsDB creates a new login attempts repository
func NewLoginAttemptsDB(db *DB) *LoginAttemptsDB {
	return &LoginAttemptsDB{db: db}
}

// RecordAttempt records a failed login attempt
// Only failed attempts are recorded for lockout tracking and audit trail
// Successful logins are tracked via users.last_login_at
// Old attempts should be cleaned up periodically (e.g., delete records older than 90 days)
// Note: Does not use tenant context since login attempts are pre-authentication
func (r *LoginAttemptsDB) RecordAttempt(ctx context.Context, email string, userID *uuid.UUID, ipAddress *string, lockedUntil *time.Time) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		_, err := q.InsertLoginAttempt(ctx, sqlc.InsertLoginAttemptParams{
			Email:       email,
			UserID:      userID,
			IpAddress:   ipAddress,
			LockedUntil: lockedUntil,
		})
		if err != nil {
			return fmt.Errorf("failed to insert login attempt: %w", err)
		}
		return nil
	})
}

// GetRecentFailedAttempts counts failed login attempts for an email within a time window
func (r *LoginAttemptsDB) GetRecentFailedAttempts(ctx context.Context, email string, since time.Time) (int64, error) {
	var count int64

	// Don't use tenant context since login attempts are pre-authentication
	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		c, err := q.GetRecentFailedAttempts(ctx, sqlc.GetRecentFailedAttemptsParams{
			Email:       email,
			AttemptedAt: since,
		})
		if err != nil {
			return fmt.Errorf("failed to get recent failed attempts: %w", err)
		}
		count = c
		return nil
	})

	return count, err
}

// GetMostRecentLockout retrieves the most recent non-null locked_until timestamp
// Returns nil if no active or recent lockouts exist
func (r *LoginAttemptsDB) GetMostRecentLockout(ctx context.Context, email string) (*time.Time, error) {
	var lockedUntil *time.Time

	// Don't use tenant context since login attempts are pre-authentication
	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		lu, err := q.GetMostRecentLockout(ctx, email)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				// No lockout found - return nil
				return nil
			}
			return fmt.Errorf("failed to get most recent lockout: %w", err)
		}

		lockedUntil = lu
		return nil
	})

	return lockedUntil, err
}

// DeleteOldLoginAttempts removes login attempts older than the specified time
// This should be called periodically (e.g., daily) to clean up old audit data
// Recommended retention: 30-90 days depending on compliance requirements
func (r *LoginAttemptsDB) DeleteOldLoginAttempts(ctx context.Context, olderThan time.Time) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteOldLoginAttempts(ctx, olderThan)
		if err != nil {
			return fmt.Errorf("failed to delete old login attempts: %w", err)
		}
		return nil
	})
}
