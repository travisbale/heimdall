package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/crypto/token"
)

const registrationTokenExpiration = 24 * time.Hour

// userDB defines the interface for user database operations
type userDB interface {
	CreateUser(ctx context.Context, user *User) (*User, error)
	GetUser(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, params *UpdateUserParams) (*User, error)
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
}

type hasher interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password string, encodedHash string) error
}

type oidcService interface {
	IsSSORequired(ctx context.Context, email string) (bool, error)
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

// UserServiceConfig holds the dependencies for creating a UserService
type UserServiceConfig struct {
	UserDB               userDB
	Hasher               hasher
	EmailService         emailService
	VerificationTokenDB  tokenDB
	PasswordResetTokenDB tokenDB
	LoginAttemptsService loginAttemptsService
	OIDCService          oidcService
	Logger               logger
}

// UserService handles user registration, login, email verification, and password management
type UserService struct {
	userDB               userDB
	hasher               hasher
	emailService         emailService
	verificationTokenDB  tokenDB
	passwordResetTokenDB tokenDB
	loginAttemptsService loginAttemptsService
	oidcService          oidcService
	logger               logger
}

func NewUserService(config *UserServiceConfig) *UserService {
	return &UserService{
		userDB:               config.UserDB,
		hasher:               config.Hasher,
		emailService:         config.EmailService,
		verificationTokenDB:  config.VerificationTokenDB,
		passwordResetTokenDB: config.PasswordResetTokenDB,
		oidcService:          config.OIDCService,
		loginAttemptsService: config.LoginAttemptsService,
		logger:               config.Logger,
	}
}

// Register creates new user with email verification, rejects SSO-enforced domains
func (s *UserService) Register(ctx context.Context, email string) (*User, error) {
	if required, err := s.oidcService.IsSSORequired(ctx, email); err != nil {
		return nil, err
	} else if required {
		return nil, ErrSSORequired
	}

	var user *User

	// Check if user already exists
	user, err := s.userDB.GetUserByEmail(ctx, email)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserNotFound):
			// Create a new user under a new tenant
			tenantID := uuid.New()
			user = &User{
				TenantID:     tenantID,
				Email:        email,
				PasswordHash: "", // Empty until email is verified and password is set
				Status:       UserStatusUnverified,
			}

			user, err = s.userDB.CreateUser(ctx, user)
			if err != nil {
				return nil, fmt.Errorf("failed to create user: %w", err)
			}

		default:
			return nil, fmt.Errorf("failed to check existing user: %w", err)
		}
	}

	if user.Status != UserStatusUnverified {
		return nil, ErrDuplicateEmail
	}

	verificationToken, err := token.Generate(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	expiresAt := time.Now().Add(registrationTokenExpiration)
	_, err = s.verificationTokenDB.CreateToken(ctx, user.ID, verificationToken, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create verification token: %w", err)
	}

	if err := s.emailService.SendVerificationEmail(ctx, email, verificationToken); err != nil {
		return nil, fmt.Errorf("failed to send verification email: %w", err)
	}

	return user, nil
}

// ConfirmRegistration verifies the email verification token, sets the password, and activates the account
func (s *UserService) ConfirmRegistration(ctx context.Context, token string, password string) (*User, error) {
	verificationToken, err := s.verificationTokenDB.GetToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get verification token: %w", err)
	}

	if time.Now().After(verificationToken.ExpiresAt) {
		return nil, ErrVerificationTokenNotFound
	}

	user, err := s.userDB.GetUser(ctx, verificationToken.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}

	if user.Status != UserStatusUnverified {
		return nil, ErrAccountAlreadyVerified
	}

	passwordHash, err := s.hasher.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	activeStatus := UserStatusActive
	user, err = s.userDB.UpdateUser(ctx, &UpdateUserParams{
		ID:           verificationToken.UserID,
		PasswordHash: &passwordHash,
		Status:       &activeStatus,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to set password and activate account: %w", err)
	}

	if err := s.verificationTokenDB.DeleteToken(ctx, verificationToken.UserID); err != nil {
		s.logger.Error("failed to delete verification token", "error", err, "user_id", verificationToken.UserID)
	}

	return user, nil
}

// CreateUser creates a new user with a temporary password
func (s *UserService) CreateUser(ctx context.Context, tenantID uuid.UUID, email string) (*User, string, error) {
	tempPassword, err := token.Generate(16)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate temporary password: %w", err)
	}

	passwordHash, err := s.hasher.HashPassword(tempPassword)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash password: %w", err)
	}

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

// GetScopes returns the scopes assigned to the user
func (s *UserService) GetScopes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	// Scope/permission system not yet implemented
	return []string{}, nil
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
func (s *UserService) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Get the password reset token
	resetToken, err := s.passwordResetTokenDB.GetToken(ctx, token)
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
