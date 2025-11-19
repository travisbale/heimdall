package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/travisbale/heimdall/crypto/token"
)

// Login authenticates a user and returns the active user account
func (s *UserService) Login(ctx context.Context, email, password, ipAddress string) (*User, error) {
	var ipPtr *string
	if ipAddress != "" {
		ipPtr = &ipAddress
	}

	if locked, _, err := s.loginAttemptsService.IsAccountLocked(ctx, email); err != nil {
		return nil, fmt.Errorf("failed to check account lockout status: %w", err)
	} else if locked {
		return nil, ErrAccountLocked
	}

	user, err := s.userDB.GetUserByEmail(ctx, email)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			if err := s.loginAttemptsService.RecordFailedLogin(ctx, email, nil, ipPtr, nil); err != nil {
				s.logger.Error("failed to record login attempt for non-existent user", "email", email, "error", err)
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
			if err := s.loginAttemptsService.RecordFailedLogin(ctx, email, &user.ID, ipPtr, user.LastLoginAt); err != nil {
				s.logger.Error("failed to record login attempt", "email", email, "error", err)
			}
			return nil, ErrInvalidCredentials

		default:
			return nil, fmt.Errorf("failed to verify password: %w", err)
		}
	}

	// Record successful login
	if err := s.loginAttemptsService.RecordSuccessfulLogin(ctx, email, &user.ID, ipPtr); err != nil {
		s.logger.Error("failed to record successful login", "email", email, "error", err)
	}

	// Update last login timestamp
	if err = s.userDB.UpdateLastLogin(ctx, user.ID); err != nil {
		s.logger.Error("failed to update last login", "user_id", user.ID, "error", err)
	}

	if user.Status == UserStatusUnverified {
		return nil, ErrEmailNotVerified
	}

	return user, nil
}

// InitiatePasswordReset generates a password reset token and sends a reset email
func (s *UserService) InitiatePasswordReset(ctx context.Context, email string) error {
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

	if err := s.emailService.SendPasswordResetEmail(ctx, email, resetToken); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	return nil
}

// ResetPassword validates the reset token and updates the user's password
func (s *UserService) ResetPassword(ctx context.Context, tokenStr, newPassword string) error {
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
		s.logger.Error("failed to delete reset token", "error", err, "user_id", resetToken.UserID)
	}

	return nil
}
