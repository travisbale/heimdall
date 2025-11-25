package iam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/crypto/token"
	"github.com/travisbale/heimdall/internal/events"
)

type loginAttemptsService interface {
	RecordFailedLogin(ctx context.Context, email string, userID *uuid.UUID, lastLoginAt *time.Time) error
	RecordSuccessfulLogin(ctx context.Context, email string, userID *uuid.UUID) error
	IsAccountLocked(ctx context.Context, email string) (bool, time.Time, error)
}

// PasswordService handles password-based authentication operations
type PasswordService struct {
	userDB               userDB
	hasher               hasher
	passwordResetTokenDB tokenDB
	emailClient          emailClient
	loginAttemptsService loginAttemptsService
	logger               logger
}

// PasswordServiceConfig contains all dependencies for PasswordService
type PasswordServiceConfig struct {
	UserDB               userDB
	Hasher               hasher
	PasswordResetTokenDB tokenDB
	EmailClient          emailClient
	LoginAttemptsService loginAttemptsService
	Logger               logger
}

// NewPasswordService creates a new PasswordService with the provided configuration
func NewPasswordService(config *PasswordServiceConfig) *PasswordService {
	return &PasswordService{
		userDB:               config.UserDB,
		hasher:               config.Hasher,
		passwordResetTokenDB: config.PasswordResetTokenDB,
		emailClient:          config.EmailClient,
		loginAttemptsService: config.LoginAttemptsService,
		logger:               config.Logger,
	}
}

// VerifyCredentials verifies user credentials and returns the active user account
func (s *PasswordService) VerifyCredentials(ctx context.Context, email, password string) (*User, error) {
	if locked, _, err := s.loginAttemptsService.IsAccountLocked(ctx, email); err != nil {
		return nil, fmt.Errorf("failed to check account lockout status: %w", err)
	} else if locked {
		return nil, ErrAccountLocked
	}

	user, err := s.userDB.GetUserByEmail(ctx, email)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			if err := s.loginAttemptsService.RecordFailedLogin(ctx, email, nil, nil); err != nil {
				s.logger.Error(ctx, "failed to record login attempt for non-existent user", "email", email, "error", err)
			}
			return nil, ErrInvalidCredentials
		default:
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
	}

	// Verify password before checking account status to prevent user enumeration
	err = s.hasher.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidCredentials):
			if err := s.loginAttemptsService.RecordFailedLogin(ctx, email, &user.ID, user.LastLoginAt); err != nil {
				s.logger.Error(ctx, "failed to record login attempt", "email", email, "error", err)
			}
			return nil, ErrInvalidCredentials

		default:
			return nil, fmt.Errorf("failed to verify password: %w", err)
		}
	}

	// Record successful login
	if err := s.loginAttemptsService.RecordSuccessfulLogin(ctx, email, &user.ID); err != nil {
		s.logger.Error(ctx, "failed to record successful login", "email", email, "error", err)
	}

	if err = s.userDB.UpdateLastLogin(ctx, user.ID); err != nil {
		s.logger.Error(ctx, "failed to update last login", "user_id", user.ID, "error", err)
	}

	if user.Status == UserStatusUnverified {
		return nil, ErrEmailNotVerified
	}

	s.logger.Info(ctx, events.LoginSucceeded, "user_id", user.ID, "email", email)

	return user, nil
}

// InitiatePasswordReset generates a password reset token and sends a reset email
func (s *PasswordService) InitiatePasswordReset(ctx context.Context, email string) error {
	user, err := s.userDB.GetUserByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	resetToken, err := token.Generate(32)
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	_, err = s.passwordResetTokenDB.CreateToken(ctx, user.ID, resetToken, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to create reset token: %w", err)
	}

	if err := s.emailClient.SendPasswordResetEmail(ctx, email, resetToken); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	s.logger.Info(ctx, events.PasswordResetRequested, "user_id", user.ID, "email", email)

	return nil
}

// ResetPassword validates the reset token and updates the user's password
func (s *PasswordService) ResetPassword(ctx context.Context, tokenStr, newPassword string) error {
	// Get the password reset token
	resetToken, err := s.passwordResetTokenDB.GetToken(ctx, tokenStr)
	if err != nil {
		return fmt.Errorf("invalid or expired reset token")
	}

	// Check if token has expired
	if time.Now().After(resetToken.ExpiresAt) {
		return ErrPasswordResetTokenNotFound
	}

	// Hash the new password
	passwordHash, err := s.hasher.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update the user's password
	if _, err := s.userDB.UpdateUser(ctx, &UpdateUserParams{
		ID:           resetToken.UserID,
		PasswordHash: &passwordHash,
	}); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Delete the reset token
	if err := s.passwordResetTokenDB.DeleteToken(ctx, resetToken.UserID); err != nil {
		// Log but don't fail - the password is already updated
		s.logger.Error(ctx, "failed to delete reset token", "error", err, "user_id", resetToken.UserID)
	}

	s.logger.Info(ctx, events.PasswordResetCompleted, "user_id", resetToken.UserID)

	return nil
}

// ChangePassword updates a user's password after validating their current password
func (s *PasswordService) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := s.userDB.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if err := s.hasher.VerifyPassword(oldPassword, user.PasswordHash); err != nil {
		return ErrInvalidCredentials
	}

	passwordHash, err := s.hasher.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if _, err := s.userDB.UpdateUser(ctx, &UpdateUserParams{
		ID:           userID,
		PasswordHash: &passwordHash,
	}); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	s.logger.Info(ctx, events.PasswordChanged, "user_id", userID)

	return nil
}
