package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
)

// MFASettingsDB manages MFA settings (authenticated operations)
type MFASettingsDB struct {
	db *DB
}

func NewMFASettingsDB(db *DB) *MFASettingsDB {
	return &MFASettingsDB{db: db}
}

// Create creates MFA settings for a user
func (r *MFASettingsDB) Create(ctx context.Context, userID uuid.UUID, encryptedSecret string) (*auth.MFASettings, error) {
	var result *auth.MFASettings

	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		tenantID, err := identity.GetTenant(ctx)
		if err != nil {
			return err
		}

		row, err := q.CreateMFASettings(ctx, sqlc.CreateMFASettingsParams{
			UserID:     userID,
			TenantID:   tenantID,
			TotpSecret: encryptedSecret,
		})
		if err != nil {
			return fmt.Errorf("failed to create MFA settings: %w", err)
		}

		result = &auth.MFASettings{
			UserID:         row.UserID,
			TOTPSecret:     row.TotpSecret,
			LastUsedWindow: row.LastUsedWindow,
			VerifiedAt:     row.VerifiedAt,
			LastUsedAt:     row.LastUsedAt,
		}
		return nil
	})

	return result, err
}

// GetByUserID retrieves MFA settings by user ID
func (r *MFASettingsDB) GetByUserID(ctx context.Context, userID uuid.UUID) (*auth.MFASettings, error) {
	var result *auth.MFASettings

	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetMFASettingsByUserID(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrMFANotEnabled
			}
			return fmt.Errorf("failed to get MFA settings: %w", err)
		}

		result = &auth.MFASettings{
			UserID:         row.UserID,
			TOTPSecret:     row.TotpSecret,
			LastUsedWindow: row.LastUsedWindow,
			VerifiedAt:     row.VerifiedAt,
			LastUsedAt:     row.LastUsedAt,
		}
		return nil
	})

	return result, err
}

// Update updates MFA settings
func (r *MFASettingsDB) Update(ctx context.Context, settings *auth.MFASettings) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		err := q.UpdateMFASettings(ctx, sqlc.UpdateMFASettingsParams{
			UserID:         settings.UserID,
			LastUsedWindow: settings.LastUsedWindow,
			VerifiedAt:     settings.VerifiedAt,
			LastUsedAt:     settings.LastUsedAt,
		})
		if err != nil {
			return fmt.Errorf("failed to update MFA settings: %w", err)
		}
		return nil
	})
}

// Delete deletes MFA settings for a user
func (r *MFASettingsDB) Delete(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteMFASettings(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to delete MFA settings: %w", err)
		}
		return nil
	})
}

// UpdateLastUsed updates last used window and timestamp (for replay prevention)
func (r *MFASettingsDB) UpdateLastUsed(ctx context.Context, userID uuid.UUID, window int64) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		now := time.Now()
		err := q.UpdateMFASettings(ctx, sqlc.UpdateMFASettingsParams{
			UserID:         userID,
			LastUsedWindow: &window,
			VerifiedAt:     nil,
			LastUsedAt:     &now,
		})
		if err != nil {
			return fmt.Errorf("failed to update last used: %w", err)
		}
		return nil
	})
}
