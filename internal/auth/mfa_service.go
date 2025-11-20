package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/events"
)

// Hasher hashes and verifies passwords/codes
type Hasher interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password, hash string) error
}

// MFAVerifier handles setup and verification for a specific MFA method (TOTP, WebAuthn, etc.)
type MFAVerifier interface {
	Setup(ctx context.Context, userID uuid.UUID, email string) (*MFAEnrollment, error)
	Enable(ctx context.Context, userID uuid.UUID, code string) error
	Verify(ctx context.Context, userID uuid.UUID, code string) error
}

// MFASettingsDB provides database operations for MFA settings
type MFASettingsDB interface {
	GetByUserID(ctx context.Context, userID uuid.UUID) (*MFASettings, error)
	Delete(ctx context.Context, userID uuid.UUID) error
}

// MFABackupCodesDB provides database operations for MFA backup codes
type MFABackupCodesDB interface {
	CreateBatch(ctx context.Context, userID uuid.UUID, codeHashes []string) error
	GetUnusedByUserID(ctx context.Context, userID uuid.UUID) ([]*MFABackupCode, error)
	MarkUsed(ctx context.Context, codeID uuid.UUID) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	CountUnused(ctx context.Context, userID uuid.UUID) (int, error)
}

// UsersDB provides database operations for users
type UsersDB interface {
	GetUser(ctx context.Context, userID uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, params *UpdateUserParams) (*User, error)
}

type MFAServiceCofig struct {
	MFASettingsDB MFASettingsDB
	BackupCodesDB MFABackupCodesDB
	UsersDB       UsersDB
	Verifier      MFAVerifier
	Hasher        Hasher
	Logger        logger
}

// MFAService manages multi-factor authentication
type MFAService struct {
	mfaSettingsDB MFASettingsDB
	backupCodesDB MFABackupCodesDB
	usersDB       UsersDB
	verifier      MFAVerifier
	hasher        Hasher
	logger        logger
}

// NewMFAService creates a new MFA service
func NewMFAService(config *MFAServiceCofig) *MFAService {
	return &MFAService{
		mfaSettingsDB: config.MFASettingsDB,
		backupCodesDB: config.BackupCodesDB,
		usersDB:       config.UsersDB,
		verifier:      config.Verifier,
		hasher:        config.Hasher,
		logger:        config.Logger,
	}
}

// SetupMFA initiates MFA setup by generating secret, QR code, and backup codes
func (s *MFAService) SetupMFA(ctx context.Context, userID uuid.UUID) (*MFAEnrollment, error) {
	settings, err := s.mfaSettingsDB.GetByUserID(ctx, userID)
	if err == nil && settings.VerifiedAt != nil {
		return nil, ErrMFAAlreadyEnabled
	}

	user, err := s.usersDB.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	setupResp, err := s.verifier.Setup(ctx, userID, user.Email)
	if err != nil {
		return nil, err
	}

	backupCodes := make([]string, 10)
	codeHashes := make([]string, 10)
	for i := range 10 {
		max := big.NewInt(100000000)
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		code := fmt.Sprintf("%08d", n.Int64())
		backupCodes[i] = code

		hash, err := s.hasher.HashPassword(code)
		if err != nil {
			return nil, fmt.Errorf("failed to hash backup code: %w", err)
		}
		codeHashes[i] = hash
	}

	if err := s.backupCodesDB.CreateBatch(ctx, userID, codeHashes); err != nil {
		return nil, err
	}

	setupResp.BackupCodes = backupCodes
	s.logger.Info(ctx, events.MFASetupStarted, "user_id", userID)

	return setupResp, nil
}

// EnableMFA validates MFA setup code and enables MFA
func (s *MFAService) EnableMFA(ctx context.Context, userID uuid.UUID, code string) error {
	if err := s.verifier.Enable(ctx, userID, code); err != nil {
		return err
	}

	s.logger.Info(ctx, events.MFAEnabled, "user_id", userID)
	return nil
}

// DisableMFA disables MFA for a user (requires password and TOTP/backup code)
func (s *MFAService) DisableMFA(ctx context.Context, userID uuid.UUID, password, code string) error {
	user, err := s.usersDB.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	if err := s.hasher.VerifyPassword(password, user.PasswordHash); err != nil {
		return ErrInvalidCredentials
	}

	err = s.VerifyMFA(ctx, userID, code)
	if err != nil {
		return err
	}

	// Delete MFA settings and backup codes
	if err := s.mfaSettingsDB.Delete(ctx, userID); err != nil {
		return err
	}

	if err := s.backupCodesDB.DeleteByUserID(ctx, userID); err != nil {
		return err
	}

	s.logger.Info(ctx, events.MFADisabled, "user_id", userID)
	return nil
}

// RegenerateBackupCodes generates new backup codes (requires password)
func (s *MFAService) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, password string) ([]string, error) {
	user, err := s.usersDB.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	if err := s.hasher.VerifyPassword(password, user.PasswordHash); err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := s.backupCodesDB.DeleteByUserID(ctx, userID); err != nil {
		return nil, err
	}

	backupCodes := make([]string, 10)
	codeHashes := make([]string, 10)
	for i := range 10 {
		max := big.NewInt(100000000)
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		code := fmt.Sprintf("%08d", n.Int64())
		backupCodes[i] = code

		hash, err := s.hasher.HashPassword(code)
		if err != nil {
			return nil, fmt.Errorf("failed to hash backup code: %w", err)
		}
		codeHashes[i] = hash
	}

	if err := s.backupCodesDB.CreateBatch(ctx, userID, codeHashes); err != nil {
		return nil, err
	}

	s.logger.Info(ctx, events.BackupCodesRegenerated, "user_id", userID)
	return backupCodes, nil
}

// GetStatus returns MFA status for a user
func (s *MFAService) GetStatus(ctx context.Context, userID uuid.UUID) (*MFAStatus, error) {
	settings, err := s.mfaSettingsDB.GetByUserID(ctx, userID)
	if err != nil {
		if err == ErrMFANotEnabled {
			return &MFAStatus{
				VerifiedAt:           nil,
				BackupCodesRemaining: 0,
			}, nil
		}
		return nil, err
	}

	count, err := s.backupCodesDB.CountUnused(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &MFAStatus{
		VerifiedAt:           settings.VerifiedAt,
		BackupCodesRemaining: count,
	}, nil
}

// VerifyMFA tries TOTP code first, then backup code
func (s *MFAService) VerifyMFA(ctx context.Context, userID uuid.UUID, code string) error {
	// Verify TOTP
	err := s.verifier.Verify(ctx, userID, code)
	if err == nil {
		return nil
	}

	// Replay attack - return immediately, don't try backup codes
	if err == ErrMFACodeAlreadyUsed {
		return err
	}

	// Only try backup codes if TOTP code was invalid (not other errors)
	if err != ErrInvalidMFACode {
		return err
	}

	// Verify backup code
	backupCodes, err := s.backupCodesDB.GetUnusedByUserID(ctx, userID)
	if err != nil {
		return err
	}

	if len(backupCodes) == 0 {
		return ErrInvalidBackupCode
	}

	var matchedCode *MFABackupCode
	for _, backupCode := range backupCodes {
		err := s.hasher.VerifyPassword(code, backupCode.CodeHash)
		if err == nil {
			matchedCode = backupCode
			break
		}
	}

	if matchedCode == nil {
		return ErrInvalidBackupCode
	}

	if err := s.backupCodesDB.MarkUsed(ctx, matchedCode.ID); err != nil {
		return err
	}

	s.logger.Info(ctx, events.BackupCodeUsed, "user_id", userID, "backup_code_id", matchedCode.ID)
	return nil
}
