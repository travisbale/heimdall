package iam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// sessionRevoker signs a user out everywhere. A password change has to reach the
// sessions the old password created, or an attacker keeps their refresh token.
type sessionRevoker interface {
	RevokeAllSessions(ctx context.Context, userID uuid.UUID) error
}

// PasswordService handles password-based authentication operations
// strengthChecker is a dependency so a test can set a password without reaching the network.
type strengthChecker interface {
	Validate(ctx context.Context, password string) error
}

type PasswordService struct {
	UserDB               userDB
	StrengthChecker      strengthChecker
	Hasher               hasher
	PasswordResetTokenDB tokenDB
	EmailClient          emailClient
	LoginAttemptsService loginAttemptsService
	SessionRevoker       sessionRevoker
	Logger               *slog.Logger
}

// revokeSessions signs the user out of every session. Failure is logged rather than
// returned: the password has already changed, and reporting an error would suggest it
// had not. It does leave stale sessions alive, so it is logged at error level.
func (s *PasswordService) revokeSessions(ctx context.Context, userID uuid.UUID) {
	if s.SessionRevoker == nil {
		return
	}
	if err := s.SessionRevoker.RevokeAllSessions(ctx, userID); err != nil {
		s.Logger.ErrorContext(ctx, "failed to revoke sessions after password change", "user_id", userID, "error", err)
	}
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
			return nil, fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
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
			return nil, fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
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

	// Only the hash is stored: the token is a bearer credential, so a leaked table (or
	// backup, or replica) must not yield working reset links. The user gets the secret.
	expiresAt := time.Now().Add(1 * time.Hour)
	_, err = s.PasswordResetTokenDB.CreateToken(ctx, user.ID, token.Hash(resetToken), expiresAt)
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
	// Before hashing, so a refused password never reaches storage.
	if err := s.checkStrength(ctx, newPassword); err != nil {
		return err
	}
	// The user holds the plaintext token from their email; only its hash is stored.
	resetToken, err := s.PasswordResetTokenDB.GetToken(ctx, token.Hash(tokenStr))
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

	// Every existing session was created under the old password.
	s.revokeSessions(ctx, resetToken.UserID)

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
	if err := s.checkStrength(ctx, newPassword); err != nil {
		return err
	}
	user, err := s.UserDB.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if err := s.Hasher.Verify(oldPassword, user.PasswordHash); err != nil {
		if errors.Is(err, ErrMismatchedHash) {
			return fmt.Errorf("%w: %v", ErrInvalidCredentials, err)
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

	s.revokeSessions(ctx, userID)

	s.Logger.InfoContext(ctx, events.PasswordChanged, "user_id", userID)

	return nil
}

// A nil checker leaves the rule off; internal/app is what turns it on.
func (s *PasswordService) checkStrength(ctx context.Context, password string) error {
	if s.StrengthChecker == nil {
		return nil
	}
	if err := s.StrengthChecker.Validate(ctx, password); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPassword, err)
	}
	return nil
}
