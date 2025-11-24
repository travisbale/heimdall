package totp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"image/png"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/travisbale/heimdall/internal/auth"
)

// cipher handles encryption and decryption of TOTP secrets
type cipher interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// MFASettingsDB provides database operations for MFA settings
type MFASettingsDB interface {
	Create(ctx context.Context, userID uuid.UUID, encryptedSecret string) (*auth.MFASettings, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) (*auth.MFASettings, error)
	Update(ctx context.Context, settings *auth.MFASettings) error
}

// Verifier implements TOTP-based MFA verification
type Verifier struct {
	mfaSettingsDB MFASettingsDB
	cipher        cipher
	validateOpts  totp.ValidateOpts
}

// NewVerifier creates a new TOTP verifier with configurable period (0 = default 30s)
func NewVerifier(db MFASettingsDB, cipher cipher, period uint) *Verifier {
	return &Verifier{
		mfaSettingsDB: db,
		cipher:        cipher,
		validateOpts: totp.ValidateOpts{
			Period: period,
			Digits: otp.DigitsSix,
		},
	}
}

// Setup generates TOTP secret and QR code for MFA enrollment
func (v *Verifier) Setup(ctx context.Context, userID uuid.UUID, email string) (*auth.MFAEnrollment, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}
	secretBase32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Heimdall",
		AccountName: email,
		Secret:      secret,
		Period:      v.validateOpts.Period,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	img, err := key.Image(256, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR image: %w", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("failed to encode QR image: %w", err)
	}
	qrCode := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	encryptedSecret, err := v.cipher.Encrypt(secretBase32)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	if _, err := v.mfaSettingsDB.Create(ctx, userID, encryptedSecret); err != nil {
		return nil, err
	}

	return &auth.MFAEnrollment{
		Secret: secretBase32,
		QRCode: qrCode,
	}, nil
}

// Enable validates initial TOTP code and enables MFA
func (v *Verifier) Enable(ctx context.Context, userID uuid.UUID, code string) error {
	settings, err := v.mfaSettingsDB.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	if settings.VerifiedAt != nil {
		return auth.ErrMFAAlreadyEnabled
	}

	secret, err := v.cipher.Decrypt(settings.TOTPSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt secret: %w", err)
	}

	valid, err := totp.ValidateCustom(code, secret, time.Now(), v.validateOpts)
	if err != nil {
		return fmt.Errorf("%w: %v", auth.ErrInvalidMFACode, err)
	}

	if !valid {
		return auth.ErrInvalidMFACode
	}

	// Mark code as used to prevent replay during immediate login
	now := time.Now()
	currentWindow := now.Unix() / int64(v.validateOpts.Period)
	settings.VerifiedAt = &now
	settings.LastUsedWindow = &currentWindow
	settings.LastUsedAt = &now

	return v.mfaSettingsDB.Update(ctx, settings)
}

// Verify validates TOTP code during login with replay prevention
func (v *Verifier) Verify(ctx context.Context, userID uuid.UUID, code string) error {
	settings, err := v.mfaSettingsDB.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	if settings.VerifiedAt == nil {
		return auth.ErrMFANotEnabled
	}

	secret, err := v.cipher.Decrypt(settings.TOTPSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt secret: %w", err)
	}

	valid, err := totp.ValidateCustom(code, secret, time.Now(), v.validateOpts)
	if err != nil {
		return fmt.Errorf("%w: %v", auth.ErrInvalidMFACode, err)
	}

	if !valid {
		return auth.ErrInvalidMFACode
	}

	// Replay prevention: check if code was already used in this time window
	currentWindow := time.Now().Unix() / int64(v.validateOpts.Period)
	if settings.LastUsedWindow != nil && currentWindow <= *settings.LastUsedWindow {
		return auth.ErrMFACodeAlreadyUsed
	}

	now := time.Now()
	settings.LastUsedWindow = &currentWindow
	settings.LastUsedAt = &now

	return v.mfaSettingsDB.Update(ctx, settings)
}
