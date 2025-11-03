package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/sqlc"
)

// VerificationTokensDB handles database operations for verification tokens
type VerificationTokensDB struct {
	db *DB
}

// NewVerificationTokensDB creates a new verification tokens repository
func NewVerificationTokensDB(db *DB) *VerificationTokensDB {
	return &VerificationTokensDB{db: db}
}

// CreateVerificationToken creates a new verification token for a user
// If a token already exists, it will be replaced
// Note: Does not use tenant context since verification tokens are accessed without tenant scope
func (r *VerificationTokensDB) CreateVerificationToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*auth.VerificationToken, error) {
	var result *auth.VerificationToken

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		userPgID := pgtype.UUID{}
		if err := userPgID.Scan(userID.String()); err != nil {
			return fmt.Errorf("invalid user ID: %w", err)
		}

		expiresPgTime := pgtype.Timestamptz{}
		if err := expiresPgTime.Scan(expiresAt); err != nil {
			return fmt.Errorf("invalid expiration time: %w", err)
		}

		row, err := q.CreateVerificationToken(ctx, sqlc.CreateVerificationTokenParams{
			UserID:    userPgID,
			Token:     token,
			ExpiresAt: expiresPgTime,
		})
		if err != nil {
			return fmt.Errorf("failed to create verification token: %w", err)
		}

		rowUserID, err := uuid.FromBytes(row.UserID.Bytes[:])
		if err != nil {
			return fmt.Errorf("invalid user ID in response: %w", err)
		}

		result = &auth.VerificationToken{
			UserID:    rowUserID,
			Token:     row.Token,
			ExpiresAt: row.ExpiresAt.Time,
			CreatedAt: row.CreatedAt.Time,
		}
		return nil
	})

	return result, err
}

// GetVerificationToken retrieves a verification token by its token string
// Note: Does not use tenant context since verification tokens are accessed without tenant scope
func (r *VerificationTokensDB) GetVerificationToken(ctx context.Context, token string) (*auth.VerificationToken, error) {
	var result *auth.VerificationToken

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetVerificationToken(ctx, token)
		if err != nil {
			return fmt.Errorf("failed to get verification token: %w", err)
		}

		rowUserID, err := uuid.FromBytes(row.UserID.Bytes[:])
		if err != nil {
			return fmt.Errorf("invalid user ID in token: %w", err)
		}

		result = &auth.VerificationToken{
			UserID:    rowUserID,
			Token:     row.Token,
			ExpiresAt: row.ExpiresAt.Time,
			CreatedAt: row.CreatedAt.Time,
		}
		return nil
	})

	return result, err
}

// DeleteVerificationToken deletes a verification token for a user
// Note: Does not use tenant context since verification tokens are accessed without tenant scope
func (r *VerificationTokensDB) DeleteVerificationToken(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		userPgID := pgtype.UUID{}
		if err := userPgID.Scan(userID.String()); err != nil {
			return fmt.Errorf("invalid user ID: %w", err)
		}

		if err := q.DeleteVerificationToken(ctx, userPgID); err != nil {
			return fmt.Errorf("failed to delete verification token: %w", err)
		}
		return nil
	})
}
