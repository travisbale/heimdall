package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/sqlc"
)

// PasswordResetTokensDB handles database operations for password reset tokens
type PasswordResetTokensDB struct {
	db *DB
}

// NewPasswordResetTokensDB creates a new password reset tokens repository
func NewPasswordResetTokensDB(db *DB) *PasswordResetTokensDB {
	return &PasswordResetTokensDB{db: db}
}

// CreateToken creates a new password reset token for a user or replaces an existing one
// Note: Does not use tenant context since password reset tokens are accessed without tenant scope
func (r *PasswordResetTokensDB) CreateToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*auth.Token, error) {
	var result *auth.Token

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		row, err := q.CreatePasswordResetToken(ctx, sqlc.CreatePasswordResetTokenParams{
			UserID:    userID,
			Token:     token,
			ExpiresAt: expiresAt,
		})
		if err != nil {
			return fmt.Errorf("failed to create password reset token: %w", err)
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

// GetToken retrieves a password reset token by its token string
// Note: Does not use tenant context since password reset tokens are accessed without tenant scope
func (r *PasswordResetTokensDB) GetToken(ctx context.Context, token string) (*auth.Token, error) {
	var result *auth.Token

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetPasswordResetToken(ctx, token)
		if err != nil {
			return fmt.Errorf("failed to get password reset token: %w", err)
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

// DeleteToken deletes a password reset token for a user
// Note: Does not use tenant context since password reset tokens are accessed without tenant scope
func (r *PasswordResetTokensDB) DeleteToken(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		if err := q.DeletePasswordResetToken(ctx, userID); err != nil {
			return fmt.Errorf("failed to delete password reset token: %w", err)
		}
		return nil
	})
}
