package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
)

// MFABackupCodesDB manages MFA backup codes (authenticated operations)
type MFABackupCodesDB struct {
	db *DB
}

func NewMFABackupCodesDB(db *DB) *MFABackupCodesDB {
	return &MFABackupCodesDB{db: db}
}

// CreateBatch creates multiple backup codes using batch insert
func (r *MFABackupCodesDB) CreateBatch(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		params := make([]sqlc.CreateBackupCodesParams, len(codeHashes))
		for i, codeHash := range codeHashes {
			params[i] = sqlc.CreateBackupCodesParams{
				UserID:   userID,
				CodeHash: codeHash,
			}
		}

		batchResults := q.CreateBackupCodes(ctx, params)
		if err := batchResults.Close(); err != nil {
			return fmt.Errorf("failed to create backup codes: %w", err)
		}
		return nil
	})
}

// GetUnusedByUserID retrieves all unused backup codes for a user
func (r *MFABackupCodesDB) GetUnusedByUserID(ctx context.Context, userID uuid.UUID) ([]*auth.MFABackupCode, error) {
	var result []*auth.MFABackupCode

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		rows, err := q.GetUnusedBackupCodesByUserID(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to get unused backup codes: %w", err)
		}

		result = make([]*auth.MFABackupCode, len(rows))
		for i, row := range rows {
			result[i] = &auth.MFABackupCode{
				ID:       row.ID,
				UserID:   row.UserID,
				CodeHash: row.CodeHash,
				Used:     row.Used,
				UsedAt:   row.UsedAt,
			}
		}
		return nil
	})

	return result, err
}

// MarkUsed marks a backup code as used
func (r *MFABackupCodesDB) MarkUsed(ctx context.Context, codeID uuid.UUID) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.MarkBackupCodeUsed(ctx, codeID)
		if err != nil {
			return fmt.Errorf("failed to mark backup code as used: %w", err)
		}
		return nil
	})
}

// DeleteByUserID deletes all backup codes for a user
func (r *MFABackupCodesDB) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteBackupCodesByUserID(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to delete backup codes: %w", err)
		}
		return nil
	})
}

// CountUnused counts unused backup codes for a user
func (r *MFABackupCodesDB) CountUnused(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int64

	err := r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		result, err := q.CountUnusedBackupCodes(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to count unused backup codes: %w", err)
		}
		count = result
		return nil
	})

	return int(count), err
}
