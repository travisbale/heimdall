package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
)

// VerificationTokensDB handles database operations for verification tokens
type VerificationTokensDB struct {
	db *DB
}

// NewVerificationTokensDB creates a new verification tokens repository
func NewVerificationTokensDB(db *DB) *VerificationTokensDB {
	return &VerificationTokensDB{db: db}
}

// CreateToken creates a new verification token for a user
// If a token already exists, it will be replaced
// Note: Does not use tenant context since verification tokens are accessed without tenant scope
func (r *VerificationTokensDB) CreateToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*auth.Token, error) {
	var result *auth.Token

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		row, err := q.CreateVerificationToken(ctx, sqlc.CreateVerificationTokenParams{
			UserID:    userID,
			Token:     token,
			ExpiresAt: expiresAt,
		})
		if err != nil {
			return fmt.Errorf("failed to create verification token: %w", err)
		}

		result = &auth.Token{
			UserID:    row.UserID,
			Token:     row.Token,
			ExpiresAt: row.ExpiresAt,
			CreatedAt: row.CreatedAt,
		}
		return nil
	})

	return result, err
}

// GetToken retrieves a verification token by its token string
// Note: Does not use tenant context since verification tokens are accessed without tenant scope
func (r *VerificationTokensDB) GetToken(ctx context.Context, token string) (*auth.Token, error) {
	var result *auth.Token

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetVerificationToken(ctx, token)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrVerificationTokenNotFound
			}
			return fmt.Errorf("failed to get verification token: %w", err)
		}

		result = &auth.Token{
			UserID:    row.UserID,
			Token:     row.Token,
			ExpiresAt: row.ExpiresAt,
			CreatedAt: row.CreatedAt,
		}
		return nil
	})

	return result, err
}

// DeleteToken deletes a verification token for a user
// Note: Does not use tenant context since verification tokens are accessed without tenant scope
func (r *VerificationTokensDB) DeleteToken(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		if err := q.DeleteVerificationToken(ctx, userID); err != nil {
			return fmt.Errorf("failed to delete verification token: %w", err)
		}
		return nil
	})
}

// DeleteExpiredTokens deletes all expired verification tokens
// Note: Does not use tenant context since verification tokens are accessed without tenant scope
func (r *VerificationTokensDB) DeleteExpiredTokens(ctx context.Context) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		if err := q.DeleteExpiredVerificationTokens(ctx); err != nil {
			return fmt.Errorf("failed to delete expired verification tokens: %w", err)
		}
		return nil
	})
}
