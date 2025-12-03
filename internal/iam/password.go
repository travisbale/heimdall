package iam

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/knowhere/crypto/token"
)

type loginAttemptsService interface {
	RecordFailedLogin(ctx context.Context, email string, userID *uuid.UUID, lastLoginAt *time.Time) error
	RecordSuccessfulLogin(ctx context.Context, userID uuid.UUID) error
	IsAccountLocked(ctx context.Context, email string) (bool, time.Time, error)
}

// PasswordService handles password-based authentication operations
type PasswordService struct {
	UserDB               userDB
	Hasher               hasher
	PasswordResetTokenDB tokenDB
	EmailClient          emailClient
	LoginAttemptsService loginAttemptsService
	Logger               logger
}

// VerifyCredentials verifies user credentials and returns the active user account
func (s *PasswordService) VerifyCredentials(ctx context.Context, email, password string) (*User, error) {
	if locked, _, err := s.LoginAttemptsService.IsAccountLocked(ctx, email); err != nil {
		return nil, fmt.Errorf("failed to check account lockout status: %w", err)
	} else if locked {
		return nil, ErrAccountLocked
	}

	user, err := s.UserDB.GetUserByEmail(ctx, email)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			if err := s.LoginAttemptsService.RecordFailedLogin(ctx, email, nil, nil); err != nil {
				s.Logger.ErrorContext(ctx, "failed to record login attempt for non-existent user", "email", email, "error", err)
			}
			return nil, ErrInvalidCredentials
		default:
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
	}

	// Verify password before checking account status to prevent user enumeration
	if err := s.Hasher.Verify(password, user.PasswordHash); err != nil {
		if errors.Is(err, ErrMismatchedHash) {
			if err := s.LoginAttemptsService.RecordFailedLogin(ctx, email, &user.ID, user.LastLoginAt); err != nil {
				s.Logger.ErrorContext(ctx, "failed to record login attempt", "email", email, "error", err)
			}
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to verify password: %w", err)
	}

	// Clear failed login attempts after successful authentication
	if err := s.LoginAttemptsService.RecordSuccessfulLogin(ctx, user.ID); err != nil {
		s.Logger.ErrorContext(ctx, "failed to clear login attempts", "user_id", user.ID, "error", err)
	}

	if err = s.UserDB.UpdateLastLogin(ctx, user.ID); err != nil {
		s.Logger.ErrorContext(ctx, "failed to update last login", "user_id", user.ID, "error", err)
	}

	if user.Status == UserStatusUnverified {
		return nil, ErrEmailNotVerified
	}

	return user, nil
}

// InitiatePasswordReset generates a password reset token and sends a reset email
func (s *PasswordService) InitiatePasswordReset(ctx context.Context, email string) error {
	user, err := s.UserDB.GetUserByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	resetToken, err := token.Generate(32)
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	_, err = s.PasswordResetTokenDB.CreateToken(ctx, user.ID, resetToken, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to create reset token: %w", err)
	}

	if err := s.EmailClient.SendPasswordResetEmail(ctx, email, resetToken); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	s.Logger.InfoContext(ctx, events.PasswordResetRequested, "user_id", user.ID, "email", email)

	return nil
}

// ResetPassword validates the reset token and updates the user's password
func (s *PasswordService) ResetPassword(ctx context.Context, tokenStr, newPassword string) error {
	// Get the password reset token
	resetToken, err := s.PasswordResetTokenDB.GetToken(ctx, tokenStr)
	if err != nil {
		return fmt.Errorf("invalid or expired reset token")
	}

	// Check if token has expired
	if time.Now().After(resetToken.ExpiresAt) {
		return ErrPasswordResetTokenNotFound
	}

	// Hash the new password
	passwordHash, err := s.Hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update the user's password
	if _, err := s.UserDB.UpdateUser(ctx, &UpdateUserParams{
		ID:           resetToken.UserID,
		PasswordHash: &passwordHash,
	}); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Delete the reset token
	if err := s.PasswordResetTokenDB.DeleteToken(ctx, resetToken.UserID); err != nil {
		// Log but don't fail - the password is already updated
		s.Logger.ErrorContext(ctx, "failed to delete reset token", "error", err, "user_id", resetToken.UserID)
	}

	s.Logger.InfoContext(ctx, events.PasswordResetCompleted, "user_id", resetToken.UserID)

	return nil
}

// ChangePassword updates a user's password after validating their current password
func (s *PasswordService) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := s.UserDB.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if err := s.Hasher.Verify(oldPassword, user.PasswordHash); err != nil {
		if errors.Is(err, ErrMismatchedHash) {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("failed to verify password: %w", err)
	}

	passwordHash, err := s.Hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if _, err := s.UserDB.UpdateUser(ctx, &UpdateUserParams{
		ID:           userID,
		PasswordHash: &passwordHash,
	}); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	s.Logger.InfoContext(ctx, events.PasswordChanged, "user_id", userID)

	return nil
}
