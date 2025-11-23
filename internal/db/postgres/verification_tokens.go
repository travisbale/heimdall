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

// VerificationTokensDB manages email verification tokens (pre-authentication operation)
type VerificationTokensDB struct {
	db *DB
}

func NewVerificationTokensDB(db *DB) *VerificationTokensDB {
	return &VerificationTokensDB{db: db}
}

// CreateToken creates or replaces verification token (user_id is PK, enforces one token per user)
func (r *VerificationTokensDB) CreateToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*auth.UserToken, error) {
	var result *auth.UserToken

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		row, err := q.CreateVerificationToken(ctx, sqlc.CreateVerificationTokenParams{
			UserID:    userID,
			Token:     token,
			ExpiresAt: expiresAt,
		})
		if err != nil {
			return fmt.Errorf("failed to create verification token: %w", err)
		}

		result = &auth.UserToken{
			UserID:    row.UserID,
			Token:     row.Token,
			ExpiresAt: row.ExpiresAt,
		}
		return nil
	})

	return result, err
}

// GetToken retrieves token by token string (pre-authentication, no tenant context)
func (r *VerificationTokensDB) GetToken(ctx context.Context, token string) (*auth.UserToken, error) {
	var result *auth.UserToken

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetVerificationToken(ctx, token)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrVerificationTokenNotFound
			}
			return fmt.Errorf("failed to get verification token: %w", err)
		}

		result = &auth.UserToken{
			UserID:    row.UserID,
			Token:     row.Token,
			ExpiresAt: row.ExpiresAt,
		}
		return nil
	})

	return result, err
}

// DeleteToken removes verification token after successful email confirmation
func (r *VerificationTokensDB) DeleteToken(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		if err := q.DeleteVerificationToken(ctx, userID); err != nil {
			return fmt.Errorf("failed to delete verification token: %w", err)
		}
		return nil
	})
}

// DeleteExpiredTokens cleans up expired tokens (should be called periodically via cleanup job)
func (r *VerificationTokensDB) DeleteExpiredTokens(ctx context.Context) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		if err := q.DeleteExpiredVerificationTokens(ctx); err != nil {
			return fmt.Errorf("failed to delete expired verification tokens: %w", err)
		}
		return nil
	})
}
