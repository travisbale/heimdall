package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/internal/iam"
)

// RefreshTokensDB manages refresh token storage for session tracking
type RefreshTokensDB struct {
	db *DB
}

func NewRefreshTokensDB(db *DB) *RefreshTokensDB {
	return &RefreshTokensDB{db: db}
}

// Create stores a new refresh token (pre-auth: login creates tokens)
func (r *RefreshTokensDB) Create(ctx context.Context, token *iam.RefreshToken) (*iam.RefreshToken, error) {
	var result *iam.RefreshToken

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		row, err := q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
			UserID:    token.UserID,
			TenantID:  token.TenantID,
			TokenHash: token.TokenHash,
			UserAgent: token.UserAgent,
			IpAddress: token.IPAddress,
			ExpiresAt: token.ExpiresAt,
		})
		if err != nil {
			return fmt.Errorf("failed to create refresh token: %w", err)
		}

		result = toRefreshToken(row)
		return nil
	})

	return result, err
}

// GetByHash retrieves a valid (non-revoked, non-expired) token by hash (pre-auth: token refresh)
func (r *RefreshTokensDB) GetByHash(ctx context.Context, tokenHash string) (*iam.RefreshToken, error) {
	var result *iam.RefreshToken

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetRefreshTokenByHash(ctx, tokenHash)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return iam.ErrSessionNotFound
			}
			return fmt.Errorf("failed to get refresh token: %w", err)
		}

		result = toRefreshToken(row)
		return nil
	})

	return result, err
}

// ListByUserID returns all active sessions for a user (authenticated: requires tenant context)
func (r *RefreshTokensDB) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*iam.RefreshToken, error) {
	var result []*iam.RefreshToken

	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		rows, err := q.ListUserRefreshTokens(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to list refresh tokens: %w", err)
		}

		result = make([]*iam.RefreshToken, len(rows))
		for i, row := range rows {
			result[i] = toRefreshToken(row)
		}
		return nil
	})

	return result, err
}

// UpdateLastUsed updates the last_used_at timestamp (pre-auth: called during token refresh)
func (r *RefreshTokensDB) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.UpdateRefreshTokenLastUsed(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to update last used: %w", err)
		}
		return nil
	})
}

// RevokeByID revokes a specific session (authenticated: requires tenant context)
func (r *RefreshTokensDB) RevokeByID(ctx context.Context, id uuid.UUID) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		err := q.RevokeRefreshToken(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to revoke refresh token: %w", err)
		}
		return nil
	})
}

// RevokeByHash revokes a token by its hash (pre-auth: logout with cookie token)
func (r *RefreshTokensDB) RevokeByHash(ctx context.Context, tokenHash string) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.RevokeRefreshTokenByHash(ctx, tokenHash)
		if err != nil {
			return fmt.Errorf("failed to revoke refresh token: %w", err)
		}
		return nil
	})
}

// RevokeAllByUserID revokes all sessions for a user (authenticated: sign out everywhere)
func (r *RefreshTokensDB) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		err := q.RevokeAllUserRefreshTokens(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to revoke all refresh tokens: %w", err)
		}
		return nil
	})
}

// DeleteExpired cleans up expired and old revoked tokens (cleanup job: no tenant context)
func (r *RefreshTokensDB) DeleteExpired(ctx context.Context) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteExpiredRefreshTokens(ctx)
		if err != nil {
			return fmt.Errorf("failed to delete expired refresh tokens: %w", err)
		}
		return nil
	})
}

// toRefreshToken converts sqlc model to domain model
func toRefreshToken(row sqlc.RefreshToken) *iam.RefreshToken {
	return &iam.RefreshToken{
		ID:         row.ID,
		UserID:     row.UserID,
		TenantID:   row.TenantID,
		TokenHash:  row.TokenHash,
		UserAgent:  row.UserAgent,
		IPAddress:  row.IpAddress,
		CreatedAt:  row.CreatedAt,
		LastUsedAt: row.LastUsedAt,
		ExpiresAt:  row.ExpiresAt,
		RevokedAt:  row.RevokedAt,
	}
}
