package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/crypto/token"
	"github.com/travisbale/heimdall/internal/events"
)

const (
	// DeviceTokenBytes is the number of random bytes for device tokens (256 bits)
	DeviceTokenBytes = 32

	// DeviceTokenPrefix identifies device trust tokens for secret scanning
	DeviceTokenPrefix = "hmdl_device_"

	// DeviceTrustDays is the default trust duration
	DeviceTrustDays = 30
)

// trustedDeviceDB abstracts database operations for trusted devices
type trustedDeviceDB interface {
	Create(ctx context.Context, device *TrustedDevice) (*TrustedDevice, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*TrustedDevice, error)
	UpdateLastUsed(ctx context.Context, id uuid.UUID, expiresAt time.Time, ipAddress string) error
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}

// TrustedDeviceService manages trusted device operations
type TrustedDeviceService struct {
	trustedDeviceDB trustedDeviceDB
	logger          logger
}

// TrustedDeviceServiceConfig contains dependencies for TrustedDeviceService
type TrustedDeviceServiceConfig struct {
	TrustedDeviceDB trustedDeviceDB
	Logger          logger
}

// NewTrustedDeviceService creates a new trusted device service
func NewTrustedDeviceService(config *TrustedDeviceServiceConfig) *TrustedDeviceService {
	return &TrustedDeviceService{
		trustedDeviceDB: config.TrustedDeviceDB,
		logger:          config.Logger,
	}
}

// CreateTrustedDevice creates a new trusted device entry and returns the raw token.
func (s *TrustedDeviceService) CreateTrustedDevice(ctx context.Context, device *TrustedDevice) (string, error) {
	// Generate device token with prefix
	randomPart, err := token.Generate(DeviceTokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate device token: %w", err)
	}

	fullToken := DeviceTokenPrefix + randomPart

	// Set generated fields
	device.TokenHash = token.Hash(fullToken)
	device.ExpiresAt = time.Now().Add(DeviceTrustDays * 24 * time.Hour)

	_, err = s.trustedDeviceDB.Create(ctx, device)
	if err != nil {
		return "", fmt.Errorf("failed to create trusted device: %w", err)
	}

	s.logger.InfoContext(ctx, events.TrustedDeviceCreated,
		"user_id", device.UserID,
		"tenant_id", device.TenantID,
		"ip_address", device.IPAddress)

	return fullToken, nil
}

// ValidateTrustedDevice checks if the device token is valid for the given user
func (s *TrustedDeviceService) ValidateTrustedDevice(ctx context.Context, deviceToken string, userID uuid.UUID, ipAddress string) (bool, error) {
	if deviceToken == "" {
		return false, nil
	}

	tokenHash := token.Hash(deviceToken)
	device, err := s.trustedDeviceDB.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		// Not found or expired = not trusted, not an error
		return false, nil
	}

	// Verify token belongs to this user
	if device.UserID != userID {
		return false, nil
	}

	// Update last used and extend expiration (sliding window)
	newExpiry := time.Now().Add(DeviceTrustDays * 24 * time.Hour)
	if err := s.trustedDeviceDB.UpdateLastUsed(ctx, device.ID, newExpiry, ipAddress); err != nil {
		s.logger.ErrorContext(ctx, "failed to update trusted device last used", "error", err)
		// Non-fatal: continue even if update fails
	}

	return true, nil
}

// RevokeAllTrustedDevices revokes all trusted devices for a user
func (s *TrustedDeviceService) RevokeAllTrustedDevices(ctx context.Context, userID uuid.UUID) error {
	if err := s.trustedDeviceDB.RevokeAllByUserID(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke trusted devices: %w", err)
	}

	s.logger.InfoContext(ctx, events.TrustedDeviceAllRevoked, "user_id", userID)
	return nil
}

// DeleteExpiredDevices cleans up expired and old revoked devices
func (s *TrustedDeviceService) DeleteExpiredDevices(ctx context.Context) error {
	if err := s.trustedDeviceDB.DeleteExpired(ctx); err != nil {
		return fmt.Errorf("failed to delete expired devices: %w", err)
	}

	s.logger.InfoContext(ctx, "expired trusted devices deleted")
	return nil
}
