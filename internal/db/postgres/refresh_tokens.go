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

// Create stores a new refresh token (requires tenant context from auth flow)
func (r *RefreshTokensDB) Create(ctx context.Context, token *iam.RefreshToken) (*iam.RefreshToken, error) {
	var result *iam.RefreshToken

	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		row, err := q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
			UserID:    token.UserID,
			TokenHash: token.TokenHash,
			FamilyID:  token.FamilyID,
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

// GetByHash retrieves a valid (non-revoked, non-expired) token by hash (requires tenant context)
func (r *RefreshTokensDB) GetByHash(ctx context.Context, tokenHash string) (*iam.RefreshToken, error) {
	var result *iam.RefreshToken

	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
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

// UpdateLastUsed updates the last_used_at timestamp (requires tenant context)
func (r *RefreshTokensDB) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
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

// RevokeByHash revokes a token by its hash (requires tenant context)
func (r *RefreshTokensDB) RevokeByHash(ctx context.Context, tokenHash string) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
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

// GetByHashIncludingRevoked retrieves a token by hash even if revoked (for reuse detection, requires tenant context)
func (r *RefreshTokensDB) GetByHashIncludingRevoked(ctx context.Context, tokenHash string) (*iam.RefreshToken, error) {
	var result *iam.RefreshToken

	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetRefreshTokenByHashIncludingRevoked(ctx, tokenHash)
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

// RevokeByFamilyID revokes all tokens in a family (for token reuse detection, requires tenant context)
func (r *RefreshTokensDB) RevokeByFamilyID(ctx context.Context, familyID uuid.UUID) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		err := q.RevokeRefreshTokenFamily(ctx, familyID)
		if err != nil {
			return fmt.Errorf("failed to revoke token family: %w", err)
		}
		return nil
	})
}

// toRefreshToken converts sqlc model to domain model
func toRefreshToken(row sqlc.RefreshToken) *iam.RefreshToken {
	return &iam.RefreshToken{
		ID:         row.ID,
		UserID:     row.UserID,
		TokenHash:  row.TokenHash,
		FamilyID:   row.FamilyID,
		UserAgent:  row.UserAgent,
		IPAddress:  row.IpAddress,
		CreatedAt:  row.CreatedAt,
		LastUsedAt: row.LastUsedAt,
		ExpiresAt:  row.ExpiresAt,
		RevokedAt:  row.RevokedAt,
	}
}
