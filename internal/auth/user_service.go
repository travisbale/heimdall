package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// userDB defines the interface for user database operations
type userDB interface {
	CreateUser(ctx context.Context, user *User) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status UserStatus) (*User, error)
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
}

type hasher interface {
	HashPassword(password string) (string, error)
	VerifyPassword(encodedHash string, password string) error
}

type emailService interface {
	SendVerificationEmail(ctx context.Context, email, token string) error
	SendPasswordResetEmail(ctx context.Context, email, token string) error
}

type tokenDB interface {
	CreateToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*Token, error)
	GetToken(ctx context.Context, token string) (*Token, error)
	DeleteToken(ctx context.Context, userID uuid.UUID) error
}

type loginAttemptsService interface {
	RecordFailedLogin(ctx context.Context, email string, userID *uuid.UUID, ipAddress *string, lastLoginAt *time.Time) error
	RecordSuccessfulLogin(ctx context.Context, email string, userID *uuid.UUID, ipAddress *string) error
	IsAccountLocked(ctx context.Context, email string) (bool, time.Time, error)
}

type logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// UserServiceConfig holds the dependencies for creating a UserService
type UserServiceConfig struct {
	UserDB               userDB
	Hasher               hasher
	EmailService         emailService
	VerificationTokenDB  tokenDB
	PasswordResetTokenDB tokenDB
	LoginAttemptsService loginAttemptsService
	Logger               logger
}

// UserService handles authentication business logic
type UserService struct {
	userDB               userDB
	hasher               hasher
	emailService         emailService
	verificationTokenDB  tokenDB
	passwordResetTokenDB tokenDB
	loginAttemptsService loginAttemptsService
	logger               logger
}

// NewUserService creates a new authentication service
func NewUserService(config *UserServiceConfig) *UserService {
	return &UserService{
		userDB:               config.UserDB,
		hasher:               config.Hasher,
		emailService:         config.EmailService,
		verificationTokenDB:  config.VerificationTokenDB,
		passwordResetTokenDB: config.PasswordResetTokenDB,
		loginAttemptsService: config.LoginAttemptsService,
		logger:               config.Logger,
	}
}

// Register creates a new user account with email verification
func (s *UserService) Register(ctx context.Context, email, password string) (*User, error) {
	// Generate a new tenant ID for this user
	tenantID := uuid.New()

	// Hash the password
	passwordHash, err := s.hasher.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the user with unverified status
	user := &User{
		TenantID:     tenantID,
		Email:        email,
		PasswordHash: passwordHash,
		Status:       UserStatusUnverified,
	}

	user, err = s.userDB.CreateUser(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate verification token (24 hour expiration)
	token, err := generateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = s.verificationTokenDB.CreateToken(ctx, user.ID, token, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create verification token: %w", err)
	}

	// Send verification email (mailman handles async via River queue)
	if err := s.emailService.SendVerificationEmail(ctx, email, token); err != nil {
		return nil, fmt.Errorf("failed to send verification email: %w", err)
	}

	return user, nil
}

// ConfirmRegistration verifies the email verification token and activates the user account
// Returns the activated user so the caller can issue JWT tokens for auto-login
func (s *UserService) ConfirmRegistration(ctx context.Context, token string) (*User, error) {
	// Get the verification token
	verificationToken, err := s.verificationTokenDB.GetToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired verification token")
	}

	// Check if token has expired
	if time.Now().After(verificationToken.ExpiresAt) {
		return nil, fmt.Errorf("verification token has expired")
	}

	// Update user status to active (returns the updated user)
	user, err := s.userDB.UpdateUserStatus(ctx, verificationToken.UserID, UserStatusActive)
	if err != nil {
		return nil, fmt.Errorf("failed to activate user account: %w", err)
	}

	// Delete the verification token
	if err := s.verificationTokenDB.DeleteToken(ctx, verificationToken.UserID); err != nil {
		// Log but don't fail - the user is already activated
		fmt.Printf("Warning: failed to delete verification token: %v\n", err)
	}

	return user, nil
}

// ResendVerificationEmail generates a new verification token and sends it to the user
// Returns success even if user doesn't exist to avoid user enumeration
func (s *UserService) ResendVerificationEmail(ctx context.Context, email string) error {
	// Try to get the user by email
	user, err := s.userDB.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Don't reveal if user exists - return success
			return nil
		}
		// Database error - log but still return success to avoid enumeration
		s.logger.Error("failed to get user by email during resend verification", "email", email, "error", err)
		return nil
	}

	// Only send if user is unverified (silently succeed for other statuses)
	if user.Status != UserStatusUnverified {
		return nil
	}

	// Delete old verification token (if it exists)
	_ = s.verificationTokenDB.DeleteToken(ctx, user.ID)

	// Generate new verification token (24 hour expiration)
	token, err := generateVerificationToken()
	if err != nil {
		return fmt.Errorf("failed to generate verification token: %w", err)
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = s.verificationTokenDB.CreateToken(ctx, user.ID, token, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to create verification token: %w", err)
	}

	// Send verification email (mailman handles async via River queue)
	if err := s.emailService.SendVerificationEmail(ctx, email, token); err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	return nil
}

// generateVerificationToken generates a cryptographically secure verification token
func generateVerificationToken() (string, error) {
	// Generate 32 random bytes (256 bits)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Encode to base64 URL-safe format (no padding)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes), nil
}

// CreateUser creates a new user with a temporary password
func (s *UserService) CreateUser(ctx context.Context, tenantID uuid.UUID, email string) (*User, string, error) {
	// Generate a secure temporary password
	tempPassword, err := generateTemporaryPassword()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate temporary password: %w", err)
	}

	// Hash the password
	passwordHash, err := s.hasher.HashPassword(tempPassword)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the user
	user := &User{
		TenantID:     tenantID,
		Email:        email,
		PasswordHash: passwordHash,
		Status:       UserStatusActive,
	}

	user, err = s.userDB.CreateUser(ctx, user)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	return user, tempPassword, nil
}

// Login authenticates a user and returns a JWT token
// ipAddress is optional and used for tracking login attempts
func (s *UserService) Login(ctx context.Context, email, password, ipAddress string) (*User, error) {
	// Convert IP address to pointer (nil if empty)
	var ipPtr *string
	if ipAddress != "" {
		ipPtr = &ipAddress
	}

	// Check if account is locked before password verification to prevent user enumeration
	locked, expiresAt, err := s.loginAttemptsService.IsAccountLocked(ctx, email)
	if err != nil {
		s.logger.Error("failed to check lockout status", "email", email, "error", err)
		return nil, fmt.Errorf("failed to check account lockout status: %w", err)
	}
	if locked {
		s.logger.Info("login attempt for locked account", "email", email, "expires_at", expiresAt)
		return nil, ErrAccountLocked
	}

	// Get user by email
	user, err := s.userDB.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// User doesn't exist - record failed attempt to prevent user enumeration
			if err := s.loginAttemptsService.RecordFailedLogin(ctx, email, nil, ipPtr, nil); err != nil {
				s.logger.Error("failed to record login attempt for non-existent user", "email", email, "error", err)
			}
			return nil, ErrInvalidCredentials
		}
		// Database error - log and return error
		s.logger.Error("failed to get user by email", "email", email, "error", err)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Verify password before checking account status to prevent user enumeration
	err = s.hasher.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			// Only record failed attempt if credentials are invalid
			if err := s.loginAttemptsService.RecordFailedLogin(ctx, email, &user.ID, ipPtr, user.LastLoginAt); err != nil {
				s.logger.Error("failed to record login attempt", "email", email, "error", err)
			}

			return nil, ErrInvalidCredentials
		}

		return nil, fmt.Errorf("failed to verify password: %w", err)
	}

	// Record successful login
	if err := s.loginAttemptsService.RecordSuccessfulLogin(ctx, email, &user.ID, ipPtr); err != nil {
		s.logger.Error("failed to record successful login", "email", email, "error", err)
	}

	// Update last login timestamp
	if err = s.userDB.UpdateLastLogin(ctx, user.ID); err != nil {
		s.logger.Error("failed to update last login", "user_id", user.ID, "error", err)
	}

	// Check if email is verified (after authentication, before authorization)
	if user.Status == UserStatusUnverified {
		return nil, ErrEmailNotVerified
	}

	// Check if user is active (after authentication, before authorization)
	if user.Status != UserStatusActive {
		return nil, ErrAccountIsInactive
	}

	return user, nil
}

// GetScopes returns the scopes assigned to the user
func (s *UserService) GetScopes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return nil, nil
}

// generateTemporaryPassword generates a cryptographically secure temporary password
func generateTemporaryPassword() (string, error) {
	// Generate 16 random bytes (128 bits)
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Encode to base64 URL-safe format (no padding)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes), nil
}

// InitiatePasswordReset generates a password reset token and sends a reset email
// Note: Does not reveal whether the email exists for security reasons
func (s *UserService) InitiatePasswordReset(ctx context.Context, email string) error {
	// Try to get user by email
	user, err := s.userDB.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Don't reveal if user exists - return success
			return nil
		}
		// Database error - log but still return success to avoid enumeration
		s.logger.Error("failed to get user by email during password reset", "email", email, "error", err)
		return nil
	}

	// Generate reset token (1 hour expiration)
	token, err := generateVerificationToken()
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	_, err = s.passwordResetTokenDB.CreateToken(ctx, user.ID, token, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to create reset token: %w", err)
	}

	// Send password reset email (mailman handles async via River queue)
	if err := s.emailService.SendPasswordResetEmail(ctx, email, token); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	return nil
}

// ResetPassword validates the reset token and updates the user's password
func (s *UserService) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Get the password reset token
	resetToken, err := s.passwordResetTokenDB.GetToken(ctx, token)
	if err != nil {
		return fmt.Errorf("invalid or expired reset token")
	}

	// Check if token has expired
	if time.Now().After(resetToken.ExpiresAt) {
		return fmt.Errorf("reset token has expired")
	}

	// Hash the new password
	passwordHash, err := s.hasher.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update the user's password (this needs a new method in userDB)
	if err := s.userDB.UpdatePassword(ctx, resetToken.UserID, passwordHash); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Delete the reset token
	if err := s.passwordResetTokenDB.DeleteToken(ctx, resetToken.UserID); err != nil {
		// Log but don't fail - the password is already updated
		fmt.Printf("Warning: failed to delete reset token: %v\n", err)
	}

	return nil
}
