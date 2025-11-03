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
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status UserStatus) error
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
	Logger               logger
}

// UserService handles authentication business logic
type UserService struct {
	userDB               userDB
	hasher               hasher
	emailService         emailService
	verificationTokenDB  tokenDB
	passwordResetTokenDB tokenDB
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

	// Send verification email asynchronously
	go func() {
		// Use background context to avoid cancellation when request completes
		if err := s.emailService.SendVerificationEmail(context.Background(), email, token); err != nil {
			s.logger.Error("failed to send verification email", "email", email, "error", err)
		} else {
			s.logger.Info("verification email sent", "email", email)
		}
	}()

	return user, nil
}

// ConfirmRegistration verifies the email verification token and activates the user account
func (s *UserService) ConfirmRegistration(ctx context.Context, token string) error {
	// Get the verification token
	verificationToken, err := s.verificationTokenDB.GetToken(ctx, token)
	if err != nil {
		return fmt.Errorf("invalid or expired verification token")
	}

	// Check if token has expired
	if time.Now().After(verificationToken.ExpiresAt) {
		return fmt.Errorf("verification token has expired")
	}

	// Update user status to active
	if err := s.userDB.UpdateUserStatus(ctx, verificationToken.UserID, UserStatusActive); err != nil {
		return fmt.Errorf("failed to activate user account: %w", err)
	}

	// Delete the verification token
	if err := s.verificationTokenDB.DeleteToken(ctx, verificationToken.UserID); err != nil {
		// Log but don't fail - the user is already activated
		fmt.Printf("Warning: failed to delete verification token: %v\n", err)
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
func (s *UserService) Login(ctx context.Context, email, password string) (*User, error) {
	// Get user by email
	user, err := s.userDB.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Check if email is verified
	if user.Status == UserStatusUnverified {
		return nil, ErrEmailNotVerified
	}

	// Check if user is active
	if user.Status != UserStatusActive {
		return nil, ErrAccountIsInactive
	}

	// Verify password
	err = s.hasher.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return nil, err
		}

		return nil, fmt.Errorf("failed to verify password: %w", err)
	}

	// Update last login timestamp
	if err = s.userDB.UpdateLastLogin(ctx, user.ID); err != nil {
		// Log the error but don't fail the login
		fmt.Printf("Warning: failed to update last login: %v\n", err)
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
		// Don't reveal if user exists - log and return success
		s.logger.Info("password reset attempted for non-existent email", "email", email)
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

	// Send password reset email asynchronously
	go func() {
		if err := s.emailService.SendPasswordResetEmail(context.Background(), email, token); err != nil {
			s.logger.Error("failed to send password reset email", "email", email, "error", err)
		} else {
			s.logger.Info("password reset email sent", "email", email)
		}
	}()

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
