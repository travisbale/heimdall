package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/internal/iam"
)

// TrustedDevicesDB manages trusted device storage for MFA bypass
type TrustedDevicesDB struct {
	db *DB
}

func NewTrustedDevicesDB(db *DB) *TrustedDevicesDB {
	return &TrustedDevicesDB{db: db}
}

// Create stores a new trusted device (requires tenant context)
func (r *TrustedDevicesDB) Create(ctx context.Context, device *iam.TrustedDevice) (*iam.TrustedDevice, error) {
	var result *iam.TrustedDevice

	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		row, err := q.CreateTrustedDevice(ctx, sqlc.CreateTrustedDeviceParams{
			UserID:    device.UserID,
			TenantID:  device.TenantID,
			TokenHash: device.TokenHash,
			UserAgent: device.UserAgent,
			IpAddress: device.IPAddress,
			ExpiresAt: device.ExpiresAt,
		})
		if err != nil {
			return fmt.Errorf("failed to create trusted device: %w", err)
		}

		result = toTrustedDevice(row)
		return nil
	})

	return result, err
}

// GetByTokenHash retrieves a valid (non-revoked, non-expired) device by token hash
func (r *TrustedDevicesDB) GetByTokenHash(ctx context.Context, tokenHash string) (*iam.TrustedDevice, error) {
	var result *iam.TrustedDevice

	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetTrustedDeviceByTokenHash(ctx, tokenHash)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return iam.ErrTrustedDeviceNotFound
			}
			return fmt.Errorf("failed to get trusted device: %w", err)
		}

		result = toTrustedDevice(row)
		return nil
	})

	return result, err
}

// UpdateLastUsed updates the last_used_at, expires_at, and ip_address (requires tenant context)
func (r *TrustedDevicesDB) UpdateLastUsed(ctx context.Context, id uuid.UUID, expiresAt time.Time, ipAddress string) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		err := q.UpdateTrustedDeviceLastUsed(ctx, sqlc.UpdateTrustedDeviceLastUsedParams{
			ID:        id,
			ExpiresAt: expiresAt,
			IpAddress: ipAddress,
		})
		if err != nil {
			return fmt.Errorf("failed to update last used: %w", err)
		}
		return nil
	})
}

// RevokeAllByUserID revokes all trusted devices for a user
func (r *TrustedDevicesDB) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		err := q.RevokeAllUserTrustedDevices(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to revoke all trusted devices: %w", err)
		}
		return nil
	})
}

// DeleteExpired cleans up expired and old revoked devices (cleanup job: no tenant context)
func (r *TrustedDevicesDB) DeleteExpired(ctx context.Context) error {
	return r.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteExpiredTrustedDevices(ctx)
		if err != nil {
			return fmt.Errorf("failed to delete expired trusted devices: %w", err)
		}
		return nil
	})
}

// toTrustedDevice converts sqlc model to domain model
func toTrustedDevice(row sqlc.TrustedDevice) *iam.TrustedDevice {
	return &iam.TrustedDevice{
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
