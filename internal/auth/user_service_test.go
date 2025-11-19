package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
)

// Test Helpers

type userServiceTestFixture struct {
	service              *UserService
	userDB               *mockUserDB
	hasher               *mockHasher
	emailService         *mockEmailService
	verificationTokenDB  *mockTokenDB
	passwordResetTokenDB *mockTokenDB
	loginAttempts        *mockLoginAttemptsService
	oidcService          *mockOIDCServiceForUser
}

func newUserServiceTestFixture() *userServiceTestFixture {
	userDB := newMockUserDB()
	hasher := &mockHasher{}
	emailService := &mockEmailService{}
	verificationTokenDB := newMockTokenDB()
	passwordResetTokenDB := newMockTokenDB()
	loginAttempts := &mockLoginAttemptsService{}
	oidcService := &mockOIDCServiceForUser{}
	rbacService := newMockRBACService()

	service := NewUserService(&UserServiceConfig{
		UserDB:               userDB,
		TenantsDB:            newMockTenantsDB(),
		Hasher:               hasher,
		EmailService:         emailService,
		VerificationTokenDB:  verificationTokenDB,
		PasswordResetTokenDB: passwordResetTokenDB,
		LoginAttemptsService: loginAttempts,
		OIDCService:          oidcService,
		RBACService:          rbacService,
		Logger:               &mockLogger{},
	})

	return &userServiceTestFixture{
		service:              service,
		userDB:               userDB,
		hasher:               hasher,
		emailService:         emailService,
		verificationTokenDB:  verificationTokenDB,
		passwordResetTokenDB: passwordResetTokenDB,
		loginAttempts:        loginAttempts,
		oidcService:          oidcService,
	}
}

// Helper function to add a user to mockUserDB (adds to both maps)
func addUserToMockDB(userDB *mockUserDB, user *User) {
	userDB.users[user.ID] = user
	userDB.emails[user.Email] = user
}

// Tests

func TestRegister(t *testing.T) {
	t.Run("Success_NewUser", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		user, err := f.service.Register(ctx, "newuser@example.com")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if user.Email != "newuser@example.com" {
			t.Errorf("expected email 'newuser@example.com', got %s", user.Email)
		}

		if user.Status != UserStatusUnverified {
			t.Errorf("expected status %s, got %s", UserStatusUnverified, user.Status)
		}

		// Verify user was created in DB
		if len(f.userDB.users) != 1 {
			t.Errorf("expected 1 user in DB, got %d", len(f.userDB.users))
		}

		// Verify verification token was created
		if len(f.verificationTokenDB.tokens) != 1 {
			t.Errorf("expected 1 token in DB, got %d", len(f.verificationTokenDB.tokens))
		}

		// Verify verification email was sent
		if len(f.emailService.verificationEmails) != 1 {
			t.Errorf("expected 1 verification email sent, got %d", len(f.emailService.verificationEmails))
		}
	})

	t.Run("Success_ExistingUnverifiedUser", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		// Create existing unverified user
		tenantID := uuid.New()
		existingUser := &User{
			ID:       uuid.New(),
			TenantID: tenantID,
			Email:    "existing@example.com",
			Status:   UserStatusUnverified,
		}
		addUserToMockDB(f.userDB, existingUser)

		// Register again with same email
		user, err := f.service.Register(ctx, "existing@example.com")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if user.ID != existingUser.ID {
			t.Errorf("expected to reuse existing user")
		}

		// Verify new verification token was created
		if len(f.verificationTokenDB.tokens) != 1 {
			t.Errorf("expected 1 token in DB, got %d", len(f.verificationTokenDB.tokens))
		}

		// Verify verification email was sent
		if len(f.emailService.verificationEmails) != 1 {
			t.Errorf("expected 1 verification email sent, got %d", len(f.emailService.verificationEmails))
		}
	})

	t.Run("SSORequired", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		f.oidcService.ssoRequired = true

		_, err := f.service.Register(ctx, "user@company.com")
		if !errors.Is(err, ErrSSORequired) {
			t.Errorf("expected ErrSSORequired, got %v", err)
		}
	})

	t.Run("DuplicateEmail_ActiveUser", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		// Create existing active user
		tenantID := uuid.New()
		existingUser := &User{
			ID:       uuid.New(),
			TenantID: tenantID,
			Email:    "active@example.com",
			Status:   UserStatusActive,
		}
		addUserToMockDB(f.userDB, existingUser)

		_, err := f.service.Register(ctx, "active@example.com")
		if !errors.Is(err, ErrDuplicateEmail) {
			t.Errorf("expected ErrDuplicateEmail, got %v", err)
		}
	})
}

func TestConfirmRegistration(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		// Create unverified user
		userID := uuid.New()
		tenantID := uuid.New()
		user := &User{
			ID:       userID,
			TenantID: tenantID,
			Email:    "verify@example.com",
			Status:   UserStatusUnverified,
		}
		addUserToMockDB(f.userDB, user)

		// Create verification token
		token := "verification_token_123"
		f.verificationTokenDB.tokens[token] = &UserToken{
			UserID:    userID,
			Token:     token,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		confirmedUser, err := f.service.ConfirmRegistration(ctx, token, "newpassword123")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if confirmedUser.Status != UserStatusActive {
			t.Errorf("expected status %s, got %s", UserStatusActive, confirmedUser.Status)
		}

		if confirmedUser.PasswordHash == "" {
			t.Error("expected password hash to be set")
		}

		// Verify token was deleted
		if len(f.verificationTokenDB.tokens) != 0 {
			t.Errorf("expected token to be deleted, got %d tokens", len(f.verificationTokenDB.tokens))
		}
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		// Create unverified user
		userID := uuid.New()
		tenantID := uuid.New()
		user := &User{
			ID:       userID,
			TenantID: tenantID,
			Email:    "verify@example.com",
			Status:   UserStatusUnverified,
		}
		addUserToMockDB(f.userDB, user)

		// Create expired verification token
		token := "expired_token"
		f.verificationTokenDB.tokens[token] = &UserToken{
			UserID:    userID,
			Token:     token,
			ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
		}

		_, err := f.service.ConfirmRegistration(ctx, token, "newpassword123")
		if !errors.Is(err, ErrVerificationTokenNotFound) {
			t.Errorf("expected ErrVerificationTokenNotFound, got %v", err)
		}
	})

	t.Run("AlreadyVerified", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		// Create active user
		userID := uuid.New()
		tenantID := uuid.New()
		user := &User{
			ID:       userID,
			TenantID: tenantID,
			Email:    "active@example.com",
			Status:   UserStatusActive,
		}
		addUserToMockDB(f.userDB, user)

		// Create verification token
		token := "valid_token"
		f.verificationTokenDB.tokens[token] = &UserToken{
			UserID:    userID,
			Token:     token,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}

		_, err := f.service.ConfirmRegistration(ctx, token, "newpassword123")
		if !errors.Is(err, ErrAccountAlreadyVerified) {
			t.Errorf("expected ErrAccountAlreadyVerified, got %v", err)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		_, err := f.service.ConfirmRegistration(ctx, "nonexistent_token", "password123")
		if err == nil {
			t.Error("expected error for invalid token")
		}
	})
}

func TestCreateUser(t *testing.T) {
	t.Run("non-SSO user gets temporary password", func(t *testing.T) {
		f := newUserServiceTestFixture()

		tenantID := uuid.New()
		ctx := identity.WithTenant(context.Background(), tenantID)

		user, tempPassword, err := f.service.CreateUser(ctx, "admin@example.com", nil)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if user.Email != "admin@example.com" {
			t.Errorf("expected email 'admin@example.com', got %s", user.Email)
		}

		if user.Status != UserStatusActive {
			t.Errorf("expected status %s, got %s", UserStatusActive, user.Status)
		}

		if user.TenantID != tenantID {
			t.Errorf("expected tenant ID %s, got %s", tenantID, user.TenantID)
		}

		if tempPassword == "" {
			t.Error("expected temporary password to be generated")
		}

		if user.PasswordHash == "" {
			t.Error("expected password hash to be set")
		}

		// Verify user was created in DB
		if len(f.userDB.users) != 1 {
			t.Errorf("expected 1 user in DB, got %d", len(f.userDB.users))
		}
	})

	t.Run("SSO user does not get password", func(t *testing.T) {
		f := newUserServiceTestFixture()
		f.oidcService.ssoRequired = true

		tenantID := uuid.New()
		ctx := identity.WithTenant(context.Background(), tenantID)

		user, tempPassword, err := f.service.CreateUser(ctx, "sso@company.com", nil)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if user.Email != "sso@company.com" {
			t.Errorf("expected email 'sso@company.com', got %s", user.Email)
		}

		if user.Status != UserStatusActive {
			t.Errorf("expected status %s, got %s", UserStatusActive, user.Status)
		}

		if user.TenantID != tenantID {
			t.Errorf("expected tenant ID %s, got %s", tenantID, user.TenantID)
		}

		if tempPassword != "" {
			t.Errorf("expected no temporary password for SSO user, got %s", tempPassword)
		}

		if user.PasswordHash != "" {
			t.Errorf("expected no password hash for SSO user, got %s", user.PasswordHash)
		}

		// Verify user was created in DB
		if len(f.userDB.users) != 1 {
			t.Errorf("expected 1 user in DB, got %d", len(f.userDB.users))
		}
	})
}

func TestLogin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		// Create active user with password
		userID := uuid.New()
		tenantID := uuid.New()
		user := &User{
			ID:           userID,
			TenantID:     tenantID,
			Email:        "login@example.com",
			PasswordHash: "hashed_correctpassword",
			Status:       UserStatusActive,
		}
		addUserToMockDB(f.userDB, user)

		loggedInUser, err := f.service.Login(ctx, "login@example.com", "correctpassword", "192.168.1.1")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if loggedInUser.ID != userID {
			t.Error("expected to return the correct user")
		}

		// Verify successful login was recorded
		if len(f.loginAttempts.successfulAttempts) != 1 {
			t.Errorf("expected 1 successful attempt recorded, got %d", len(f.loginAttempts.successfulAttempts))
		}
	})

	t.Run("WrongPassword", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		// Create active user with password
		userID := uuid.New()
		tenantID := uuid.New()
		user := &User{
			ID:           userID,
			TenantID:     tenantID,
			Email:        "login@example.com",
			PasswordHash: "hashed_correctpassword",
			Status:       UserStatusActive,
		}
		addUserToMockDB(f.userDB, user)

		_, err := f.service.Login(ctx, "login@example.com", "wrongpassword", "192.168.1.1")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}

		// Verify failed login was recorded
		if len(f.loginAttempts.failedAttempts) != 1 {
			t.Errorf("expected 1 failed attempt recorded, got %d", len(f.loginAttempts.failedAttempts))
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		_, err := f.service.Login(ctx, "nonexistent@example.com", "password", "192.168.1.1")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}

		// Verify failed login was recorded
		if len(f.loginAttempts.failedAttempts) != 1 {
			t.Errorf("expected 1 failed attempt recorded, got %d", len(f.loginAttempts.failedAttempts))
		}
	})

	t.Run("AccountLocked", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		f.loginAttempts.locked = true
		f.loginAttempts.lockedUntil = time.Now().Add(30 * time.Minute)

		_, err := f.service.Login(ctx, "locked@example.com", "password", "192.168.1.1")
		if !errors.Is(err, ErrAccountLocked) {
			t.Errorf("expected ErrAccountLocked, got %v", err)
		}
	})

	t.Run("UnverifiedEmail", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		// Create unverified user with password
		userID := uuid.New()
		tenantID := uuid.New()
		user := &User{
			ID:           userID,
			TenantID:     tenantID,
			Email:        "unverified@example.com",
			PasswordHash: "hashed_password",
			Status:       UserStatusUnverified,
		}
		addUserToMockDB(f.userDB, user)

		_, err := f.service.Login(ctx, "unverified@example.com", "password", "192.168.1.1")
		if !errors.Is(err, ErrEmailNotVerified) {
			t.Errorf("expected ErrEmailNotVerified, got %v", err)
		}
	})
}

func TestInitiatePasswordReset(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		// Create active user
		userID := uuid.New()
		tenantID := uuid.New()
		user := &User{
			ID:       userID,
			TenantID: tenantID,
			Email:    "reset@example.com",
			Status:   UserStatusActive,
		}
		addUserToMockDB(f.userDB, user)

		err := f.service.InitiatePasswordReset(ctx, "reset@example.com")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify reset token was created
		if len(f.passwordResetTokenDB.tokens) != 1 {
			t.Errorf("expected 1 reset token in DB, got %d", len(f.passwordResetTokenDB.tokens))
		}

		// Verify password reset email was sent
		if len(f.emailService.passwordResetEmails) != 1 {
			t.Errorf("expected 1 password reset email sent, got %d", len(f.emailService.passwordResetEmails))
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		err := f.service.InitiatePasswordReset(ctx, "nonexistent@example.com")
		if err == nil {
			t.Error("expected error for non-existent user")
		}
	})
}

func TestResetPassword(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		// Create active user
		userID := uuid.New()
		tenantID := uuid.New()
		user := &User{
			ID:           userID,
			TenantID:     tenantID,
			Email:        "reset@example.com",
			PasswordHash: "old_hash",
			Status:       UserStatusActive,
		}
		addUserToMockDB(f.userDB, user)

		// Create password reset token
		token := "reset_token_123"
		f.passwordResetTokenDB.tokens[token] = &UserToken{
			UserID:    userID,
			Token:     token,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		err := f.service.ResetPassword(ctx, token, "newpassword123")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// Verify password was updated
		updatedUser := f.userDB.users[userID]
		if updatedUser.PasswordHash == "old_hash" {
			t.Error("expected password hash to be updated")
		}

		// Verify reset token was deleted
		if len(f.passwordResetTokenDB.tokens) != 0 {
			t.Errorf("expected reset token to be deleted, got %d tokens", len(f.passwordResetTokenDB.tokens))
		}
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		// Create active user
		userID := uuid.New()
		tenantID := uuid.New()
		user := &User{
			ID:       userID,
			TenantID: tenantID,
			Email:    "reset@example.com",
			Status:   UserStatusActive,
		}
		addUserToMockDB(f.userDB, user)

		// Create expired password reset token
		token := "expired_reset_token"
		f.passwordResetTokenDB.tokens[token] = &UserToken{
			UserID:    userID,
			Token:     token,
			ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
		}

		err := f.service.ResetPassword(ctx, token, "newpassword123")
		if !errors.Is(err, ErrPasswordResetTokenNotFound) {
			t.Errorf("expected ErrPasswordResetTokenNotFound, got %v", err)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		err := f.service.ResetPassword(ctx, "nonexistent_token", "newpassword123")
		if err == nil {
			t.Error("expected error for invalid token")
		}
	})
}
