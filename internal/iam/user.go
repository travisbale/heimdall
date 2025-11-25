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

const registrationTokenExpiration = 24 * time.Hour

type oidcService interface {
	IsSSORequired(ctx context.Context, email string) (bool, error)
}

type emailClient interface {
	SendVerificationEmail(ctx context.Context, email, token string) error
	SendPasswordResetEmail(ctx context.Context, email, token string) error
}

// UserServiceConfig holds the dependencies for creating a UserService
type UserServiceConfig struct {
	UserDB              userDB
	TenantsDB           tenantsDB
	Hasher              hasher
	EmailClient         emailClient
	VerificationTokenDB tokenDB
	OIDCService         oidcService
	RBACService         rbacService
	Logger              logger
}

// UserService handles user registration, email verification, and user management
type UserService struct {
	userDB              userDB
	tenantsDB           tenantsDB
	hasher              hasher
	emailClient         emailClient
	verificationTokenDB tokenDB
	oidcService         oidcService
	rbacService         rbacService
	logger              logger
}

func NewUserService(config *UserServiceConfig) *UserService {
	return &UserService{
		userDB:              config.UserDB,
		tenantsDB:           config.TenantsDB,
		hasher:              config.Hasher,
		emailClient:         config.EmailClient,
		verificationTokenDB: config.VerificationTokenDB,
		oidcService:         config.OIDCService,
		rbacService:         config.RBACService,
		logger:              config.Logger,
	}
}

// CreateUser creates a new user and assigns specified roles
func (s *UserService) CreateUser(ctx context.Context, user *User, roleIDs []uuid.UUID) (*User, string, error) {
	ssoRequired, err := s.oidcService.IsSSORequired(ctx, user.Email)
	if err != nil {
		return nil, "", fmt.Errorf("failed to check SSO requirement: %w", err)
	}

	// Set status based on SSO requirement
	if ssoRequired {
		user.Status = UserStatusActive
	} else {
		user.Status = UserStatusUnverified
	}

	user, err = s.userDB.CreateUser(ctx, user)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	var verificationToken string
	if !ssoRequired {
		var err error
		verificationToken, err = s.createVerificationToken(ctx, user.ID)
		if err != nil {
			return nil, "", err
		}
	}

	if len(roleIDs) > 0 {
		err = s.rbacService.SetUserRoles(ctx, user.ID, roleIDs)
		if err != nil {
			return nil, "", fmt.Errorf("failed to assign roles to user: %w", err)
		}
	}

	s.logger.Info(ctx, events.UserCreated, "user_id", user.ID, "email", user.Email, "status", user.Status)

	return user, verificationToken, nil
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
			_, user, err = s.tenantsDB.BootstrapTenant(ctx, email, UserStatusUnverified)
			if err != nil {
				return nil, fmt.Errorf("failed to bootstrap tenant: %w", err)
			}

			verificationToken, err := s.createVerificationToken(ctx, user.ID)
			if err != nil {
				return nil, err
			}

			if err := s.emailClient.SendVerificationEmail(ctx, email, verificationToken); err != nil {
				return nil, fmt.Errorf("failed to send verification email: %w", err)
			}

			return user, nil

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

	if err := s.emailClient.SendVerificationEmail(ctx, email, verificationToken); err != nil {
		return nil, fmt.Errorf("failed to send verification email: %w", err)
	}

	s.logger.Info(ctx, events.UserRegistered, "user_id", user.ID, "email", email, "tenant_id", user.TenantID)

	return user, nil
}

// VerifyEmailAndSetPassword verifies the email verification token, sets the password, and activates the account
func (s *UserService) VerifyEmailAndSetPassword(ctx context.Context, tokenStr string, password string) (*User, error) {
	verificationToken, err := s.verificationTokenDB.GetToken(ctx, tokenStr)
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
		s.logger.Error(ctx, "failed to delete verification token", "error", err, "user_id", verificationToken.UserID)
	}

	s.logger.Info(ctx, events.EmailVerified, "user_id", user.ID, "email", user.Email)

	return user, nil
}

func (s *UserService) createVerificationToken(ctx context.Context, userID uuid.UUID) (string, error) {
	verificationToken, err := token.Generate(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate verification token: %w", err)
	}

	expiresAt := time.Now().Add(registrationTokenExpiration)
	_, err = s.verificationTokenDB.CreateToken(ctx, userID, verificationToken, expiresAt)
	if err != nil {
		return "", fmt.Errorf("failed to create verification token: %w", err)
	}

	return verificationToken, nil
}
