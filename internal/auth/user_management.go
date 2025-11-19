package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/crypto/token"
	"github.com/travisbale/heimdall/identity"
)

// CreateUser creates a new user and assigns specified roles
func (s *UserService) CreateUser(ctx context.Context, email string, roleIDs []uuid.UUID) (*User, string, error) {
	ssoRequired, err := s.oidcService.IsSSORequired(ctx, email)
	if err != nil {
		return nil, "", fmt.Errorf("failed to check SSO requirement: %w", err)
	}

	tenantID, err := identity.GetTenant(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get tenant from context: %w", err)
	}

	var status UserStatus
	if ssoRequired {
		status = UserStatusActive
	} else {
		status = UserStatusUnverified
	}

	user := &User{
		TenantID: tenantID,
		Email:    email,
		Status:   status,
	}

	user, err = s.userDB.CreateUser(ctx, user)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	var verificationToken string
	if !ssoRequired {
		var err error
		verificationToken, err = token.Generate(32)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate verification token: %w", err)
		}

		expiresAt := time.Now().Add(registrationTokenExpiration)
		_, err = s.verificationTokenDB.CreateToken(ctx, user.ID, verificationToken, expiresAt)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create verification token: %w", err)
		}
	}

	if len(roleIDs) > 0 {
		err = s.rbacService.SetUserRoles(ctx, user.ID, roleIDs)
		if err != nil {
			return nil, "", fmt.Errorf("failed to assign roles to user: %w", err)
		}
	}

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
			// Create a new tenant for the user
			tenantID := uuid.New()
			_, err := s.tenantsDB.CreateTenant(ctx, tenantID)
			if err != nil {
				return nil, fmt.Errorf("failed to create tenant: %w", err)
			}

			// Create the user under the new tenant
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

			// Setup System Admin role for the first user in the tenant
			// Set tenant context for RBAC operations which require tenant isolation
			ctxWithTenant := identity.WithUser(ctx, user.ID, tenantID)
			err = s.rbacService.SetupSystemAdminRole(ctxWithTenant, user.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to setup System Admin role: %w", err)
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
func (s *UserService) ConfirmRegistration(ctx context.Context, tokenStr string, password string) (*User, error) {
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
		s.logger.Error("failed to delete verification token", "error", err, "user_id", verificationToken.UserID)
	}

	return user, nil
}
