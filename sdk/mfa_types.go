package sdk

import (
	"context"
	"fmt"
	"time"
)

// MFA code length constants
const (
	totpCodeLength   = 6
	backupCodeLength = 8
)

// MFASetupResponse contains secret, QR code, and backup codes for MFA setup
type MFASetupResponse struct {
	Secret      string   `json:"secret"`
	QRCode      string   `json:"qr_code"`
	BackupCodes []string `json:"backup_codes"`
}

// EnableMFARequest verifies TOTP code during setup
type EnableMFARequest struct {
	Code string `json:"code"`
}

// Validate validates the enable MFA request
func (r *EnableMFARequest) Validate(ctx context.Context) error {
	if err := validateRequired(r.Code, "code"); err != nil {
		return err
	}
	if len(r.Code) != totpCodeLength {
		return fmt.Errorf("code must be 6 digits")
	}
	return nil
}

// DisableMFARequest disables MFA
type DisableMFARequest struct {
	Password string `json:"password"`
	Code     string `json:"code"` // TOTP code or backup code
}

// Validate validates the disable MFA request
func (r *DisableMFARequest) Validate(ctx context.Context) error {
	if err := validateRequired(r.Password, "password"); err != nil {
		return err
	}
	return validateRequired(r.Code, "code")
}

// MFAStatus represents current MFA state
type MFAStatus struct {
	VerifiedAt           *time.Time `json:"verified_at,omitempty"`
	BackupCodesRemaining int        `json:"backup_codes_remaining"`
}

// RegenerateBackupCodesRequest regenerates backup codes
type RegenerateBackupCodesRequest struct {
	Password string `json:"password"`
}

// Validate validates the regenerate backup codes request
func (r *RegenerateBackupCodesRequest) Validate(ctx context.Context) error {
	return validateRequired(r.Password, "password")
}

// BackupCodesResponse contains new backup codes
type BackupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

// VerifyMFACodeRequest verifies MFA code
type VerifyMFACodeRequest struct {
	ChallengeToken string `json:"challenge_token"` // Challenge token from initial login
	Code           string `json:"code"`            // TOTP code (6 digits) or backup code (8 digits)
	TrustDevice    bool   `json:"trust_device"`    // Optional: trust this device for 30 days (skip MFA on next login)
}

// Validate validates the verify MFA code request
func (r *VerifyMFACodeRequest) Validate(ctx context.Context) error {
	if err := validateRequired(r.ChallengeToken, "challenge_token"); err != nil {
		return err
	}
	if err := validateRequired(r.Code, "code"); err != nil {
		return err
	}
	if len(r.Code) != totpCodeLength && len(r.Code) != backupCodeLength {
		return fmt.Errorf("code must be 6 digits (TOTP) or 8 digits (backup code)")
	}
	return nil
}

// RequiredMFASetupRequest initiates MFA setup when role requires it
type RequiredMFASetupRequest struct {
	SetupToken string `json:"setup_token"` // Setup token from login response
}

// Validate validates the required MFA setup request
func (r *RequiredMFASetupRequest) Validate(ctx context.Context) error {
	return validateRequired(r.SetupToken, "setup_token")
}

// RequiredMFAEnableRequest enables MFA after required setup
type RequiredMFAEnableRequest struct {
	SetupToken string `json:"setup_token"` // Setup token from login response
	Code       string `json:"code"`        // TOTP code to verify setup
}

// Validate validates the required MFA enable request
func (r *RequiredMFAEnableRequest) Validate(ctx context.Context) error {
	if err := validateRequired(r.SetupToken, "setup_token"); err != nil {
		return err
	}
	if err := validateRequired(r.Code, "code"); err != nil {
		return err
	}
	if len(r.Code) != totpCodeLength {
		return fmt.Errorf("code must be 6 digits")
	}
	return nil
}
