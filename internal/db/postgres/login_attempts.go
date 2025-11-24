package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
)

// LoginAttemptsDB tracks failed login attempts for progressive lockout and audit trail
type LoginAttemptsDB struct {
	db *DB
}

func NewLoginAttemptsDB(db *DB) *LoginAttemptsDB {
	return &LoginAttemptsDB{db: db}
}

// RecordAttempt logs failed login attempt with calculated lockout expiry (pre-authentication operation)
func (r *LoginAttemptsDB) RecordAttempt(ctx context.Context, email string, userID *uuid.UUID, lockedUntil *time.Time) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		_, err := q.InsertLoginAttempt(ctx, sqlc.InsertLoginAttemptParams{
			Email:       email,
			UserID:      userID,
			IpAddress:   identity.GetIPAddress(ctx),
			LockedUntil: lockedUntil,
		})
		if err != nil {
			return fmt.Errorf("failed to insert login attempt: %w", err)
		}
		return nil
	})
}

// GetRecentFailedAttempts counts failed login attempts since specified time (for lockout calculation)
func (r *LoginAttemptsDB) GetRecentFailedAttempts(ctx context.Context, email string, since time.Time) (int64, error) {
	var count int64

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

// GetMostRecentLockout returns latest lockout expiry time (nil if no active lockouts)
func (r *LoginAttemptsDB) GetMostRecentLockout(ctx context.Context, email string) (*time.Time, error) {
	var lockedUntil *time.Time

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		lu, err := q.GetMostRecentLockout(ctx, email)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // No lockout found
			}
			return fmt.Errorf("failed to get most recent lockout: %w", err)
		}

		lockedUntil = lu
		return nil
	})

	return lockedUntil, err
}

// DeleteOldLoginAttempts cleans up old audit data (recommended: retain 30-90 days for compliance)
func (r *LoginAttemptsDB) DeleteOldLoginAttempts(ctx context.Context, olderThan time.Time) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteOldLoginAttempts(ctx, olderThan)
		if err != nil {
			return fmt.Errorf("failed to delete old login attempts: %w", err)
		}
		return nil
	})
}
