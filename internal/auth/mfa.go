package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/heimdall/jwt"
)

// mfaVerifier handles setup and verification for a specific MFA method (TOTP, WebAuthn, etc.)
type mfaVerifier interface {
	Setup(ctx context.Context, userID uuid.UUID, email string) (*MFAEnrollment, error)
	Enable(ctx context.Context, userID uuid.UUID, code string) error
	Verify(ctx context.Context, userID uuid.UUID, code string) error
}

// mfaSettingsDB provides database operations for MFA settings
type mfaSettingsDB interface {
	GetByUserID(ctx context.Context, userID uuid.UUID) (*MFASettings, error)
	Delete(ctx context.Context, userID uuid.UUID) error
}

// mfaBackupCodesDB provides database operations for MFA backup codes
type mfaBackupCodesDB interface {
	CreateBatch(ctx context.Context, userID uuid.UUID, codeHashes []string) error
	GetUnusedByUserID(ctx context.Context, userID uuid.UUID) ([]*MFABackupCode, error)
	MarkUsed(ctx context.Context, codeID uuid.UUID) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	CountUnused(ctx context.Context, userID uuid.UUID) (int, error)
}

// mfaChallengeTokenValidator validates MFA challenge tokens and returns claims
type mfaChallengeTokenValidator interface {
	ValidateMFAChallengeToken(token string) (*jwt.Claims, error)
}

type MFAServiceCofig struct {
	MFASettingsDB      mfaSettingsDB
	BackupCodesDB      mfaBackupCodesDB
	UsersDB            userDB
	Verifier           mfaVerifier
	Hasher             hasher
	ChallengeValidator mfaChallengeTokenValidator
	Logger             logger
}

// MFAService manages multi-factor authentication
type MFAService struct {
	mfaSettingsDB      mfaSettingsDB
	backupCodesDB      mfaBackupCodesDB
	usersDB            userDB
	verifier           mfaVerifier
	hasher             hasher
	challengeValidator mfaChallengeTokenValidator
	logger             logger
}

// NewMFAService creates a new MFA service
func NewMFAService(config *MFAServiceCofig) *MFAService {
	return &MFAService{
		mfaSettingsDB:      config.MFASettingsDB,
		backupCodesDB:      config.BackupCodesDB,
		usersDB:            config.UsersDB,
		verifier:           config.Verifier,
		hasher:             config.Hasher,
		challengeValidator: config.ChallengeValidator,
		logger:             config.Logger,
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

	err = s.verifyMFA(ctx, userID, code)
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

// VerifyMFACode validates MFA challenge token and verifies MFA code
func (s *MFAService) VerifyMFACode(ctx context.Context, challengeToken, code string) (uuid.UUID, uuid.UUID, error) {
	claims, err := s.challengeValidator.ValidateMFAChallengeToken(challengeToken)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("%w: %v", ErrInvalidChallengeToken, err)
	}

	if err := s.verifyMFA(ctx, claims.UserID, code); err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	return claims.UserID, claims.TenantID, nil
}

// verifyMFA tries TOTP code first, then backup code
func (s *MFAService) verifyMFA(ctx context.Context, userID uuid.UUID, code string) error {
	err := s.verifier.Verify(ctx, userID, code)
	if !errors.Is(err, ErrInvalidMFACode) {
		return err
	}

	// MFA code was invalid, try backup codes
	backupCodes, err := s.backupCodesDB.GetUnusedByUserID(ctx, userID)
	if err != nil {
		return err
	}

	for _, backupCode := range backupCodes {
		err := s.hasher.VerifyPassword(code, backupCode.CodeHash)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidCredentials):
				continue
			default:
				return fmt.Errorf("failed to verify backup code: %w", err)
			}
		}

		if err := s.backupCodesDB.MarkUsed(ctx, backupCode.ID); err != nil {
			return err
		}

		s.logger.Info(ctx, events.BackupCodeUsed, "user_id", userID, "backup_code_id", backupCode.ID)
		return nil
	}

	return ErrInvalidBackupCode
}
