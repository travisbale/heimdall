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

// PasswordResetTokensDB manages password reset tokens (pre-authentication operation)
type PasswordResetTokensDB struct {
	db *DB
}

func NewPasswordResetTokensDB(db *DB) *PasswordResetTokensDB {
	return &PasswordResetTokensDB{db: db}
}

// CreateToken creates or replaces reset token (user_id is PK, enforces one token per user)
func (r *PasswordResetTokensDB) CreateToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*auth.UserToken, error) {
	var result *auth.UserToken

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		row, err := q.CreatePasswordResetToken(ctx, sqlc.CreatePasswordResetTokenParams{
			UserID:    userID,
			Token:     token,
			ExpiresAt: expiresAt,
		})
		if err != nil {
			return fmt.Errorf("failed to create password reset token: %w", err)
		}

		result = &auth.UserToken{
			UserID:    row.UserID,
			Token:     row.Token,
			ExpiresAt: row.ExpiresAt,
			CreatedAt: row.CreatedAt,
		}
		return nil
	})

	return result, err
}

// GetToken retrieves token by token string (pre-authentication, no tenant context)
func (r *PasswordResetTokensDB) GetToken(ctx context.Context, token string) (*auth.UserToken, error) {
	var result *auth.UserToken

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetPasswordResetToken(ctx, token)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrPasswordResetTokenNotFound
			}
			return fmt.Errorf("failed to get password reset token: %w", err)
		}

		result = &auth.UserToken{
			UserID:    row.UserID,
			Token:     row.Token,
			ExpiresAt: row.ExpiresAt,
			CreatedAt: row.CreatedAt,
		}
		return nil
	})

	return result, err
}

// DeleteToken removes reset token after successful password change
func (r *PasswordResetTokensDB) DeleteToken(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		if err := q.DeletePasswordResetToken(ctx, userID); err != nil {
			return fmt.Errorf("failed to delete password reset token: %w", err)
		}
		return nil
	})
}

// DeleteExpiredTokens cleans up expired tokens (should be called periodically via cleanup job)
func (r *PasswordResetTokensDB) DeleteExpiredTokens(ctx context.Context) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		if err := q.DeleteExpiredPasswordResetTokens(ctx); err != nil {
			return fmt.Errorf("failed to delete expired password reset tokens: %w", err)
		}
		return nil
	})
}
