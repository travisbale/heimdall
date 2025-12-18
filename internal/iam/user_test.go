package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/knowhere/identity"
)

type userServiceTestFixture struct {
	service             *UserService
	userDB              *mockUserDB
	hasher              *mockHasher
	emailClient         *mockEmailClient
	verificationTokenDB *mockTokenDB
	oidcService         *mockOIDCServiceForUser
}

func newUserServiceTestFixture() *userServiceTestFixture {
	userDB := newMockUserDB()
	hasher := &mockHasher{}
	emailClient := &mockEmailClient{}
	verificationTokenDB := newMockTokenDB()
	oidcService := &mockOIDCServiceForUser{}
	rbacService := newMockRBACService()
	tenantsDB := newMockTenantsDB()

	// Wire up dependencies so BootstrapTenant can properly update shared mocks
	tenantsDB.setDependencies(userDB)

	service := &UserService{
		UserDB:              userDB,
		TenantsDB:           tenantsDB,
		Hasher:              hasher,
		EmailClient:         emailClient,
		VerificationTokenDB: verificationTokenDB,
		OIDCService:         oidcService,
		RBACService:         rbacService,
		Logger:              &mockLogger{},
	}

	return &userServiceTestFixture{
		service:             service,
		userDB:              userDB,
		hasher:              hasher,
		emailClient:         emailClient,
		verificationTokenDB: verificationTokenDB,
		oidcService:         oidcService,
	}
}

// Helper function to add a user to mockUserDB (adds to both maps)
func addUserToMockDB(userDB *mockUserDB, user *User) {
	userDB.users[user.ID] = user
	userDB.emails[user.Email] = user
}

func TestRegister(t *testing.T) {
	t.Run("Success_NewUser", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		user, err := f.service.Register(ctx, "newuser@example.com", "Test", "User")
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
		if len(f.emailClient.verificationEmails) != 1 {
			t.Errorf("expected 1 verification email sent, got %d", len(f.emailClient.verificationEmails))
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
		user, err := f.service.Register(ctx, "existing@example.com", "Test", "User")
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
		if len(f.emailClient.verificationEmails) != 1 {
			t.Errorf("expected 1 verification email sent, got %d", len(f.emailClient.verificationEmails))
		}
	})

	t.Run("SSORequired", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		f.oidcService.ssoRequired = true

		_, err := f.service.Register(ctx, "user@company.com", "Test", "User")
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

		_, err := f.service.Register(ctx, "active@example.com", "Test", "User")
		if !errors.Is(err, ErrDuplicateEmail) {
			t.Errorf("expected ErrDuplicateEmail, got %v", err)
		}
	})
}

func TestVerifyEmailAndSetPassword(t *testing.T) {
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

		verifiedUser, err := f.service.VerifyEmailAndSetPassword(ctx, token, "newpassword123")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if verifiedUser == nil {
			t.Fatal("expected user to be returned")
		}
		if verifiedUser.Status != UserStatusActive {
			t.Errorf("expected status %s, got %s", UserStatusActive, verifiedUser.Status)
		}
		if verifiedUser.PasswordHash == "" {
			t.Error("expected password hash to be set")
		}

		// Verify user status was updated in database
		confirmedUser, err := f.userDB.GetUserByID(ctx, userID)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if confirmedUser.Status != UserStatusActive {
			t.Errorf("expected status %s, got %s", UserStatusActive, confirmedUser.Status)
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

		_, err := f.service.VerifyEmailAndSetPassword(ctx, token, "newpassword123")
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

		_, err := f.service.VerifyEmailAndSetPassword(ctx, token, "newpassword123")
		if !errors.Is(err, ErrAccountAlreadyVerified) {
			t.Errorf("expected ErrAccountAlreadyVerified, got %v", err)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		f := newUserServiceTestFixture()
		ctx := context.Background()

		_, err := f.service.VerifyEmailAndSetPassword(ctx, "nonexistent_token", "password123")
		if err == nil {
			t.Error("expected error for invalid token")
		}
	})
}

func TestCreateUser(t *testing.T) {
	t.Run("non-SSO user created as unverified with verification token", func(t *testing.T) {
		f := newUserServiceTestFixture()

		tenantID := uuid.New()
		ctx := identity.WithTenant(context.Background(), tenantID)

		user, verificationToken, err := f.service.CreateUser(ctx, &User{
			TenantID: tenantID,
			Email:    "admin@example.com",
		}, nil)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if user.Email != "admin@example.com" {
			t.Errorf("expected email 'admin@example.com', got %s", user.Email)
		}

		if user.Status != UserStatusUnverified {
			t.Errorf("expected status %s, got %s", UserStatusUnverified, user.Status)
		}

		if user.TenantID != tenantID {
			t.Errorf("expected tenant ID %s, got %s", tenantID, user.TenantID)
		}

		if user.PasswordHash != "" {
			t.Errorf("expected no password hash for unverified user, got %s", user.PasswordHash)
		}

		// Verify user was created in DB
		if len(f.userDB.users) != 1 {
			t.Errorf("expected 1 user in DB, got %d", len(f.userDB.users))
		}

		// Verify verification token was returned
		if verificationToken == "" {
			t.Error("expected non-empty verification token for non-SSO user")
		}

		// Verify verification token was created in DB
		if len(f.verificationTokenDB.tokens) != 1 {
			t.Errorf("expected 1 verification token in DB, got %d", len(f.verificationTokenDB.tokens))
		}
	})

	t.Run("SSO user created as active with no password or token", func(t *testing.T) {
		f := newUserServiceTestFixture()
		f.oidcService.ssoRequired = true

		tenantID := uuid.New()
		ctx := identity.WithTenant(context.Background(), tenantID)

		user, verificationToken, err := f.service.CreateUser(ctx, &User{
			TenantID: tenantID,
			Email:    "sso@company.com",
		}, nil)
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

		if user.PasswordHash != "" {
			t.Errorf("expected no password hash for SSO user, got %s", user.PasswordHash)
		}

		// Verify user was created in DB
		if len(f.userDB.users) != 1 {
			t.Errorf("expected 1 user in DB, got %d", len(f.userDB.users))
		}

		// Verify no verification token was returned for SSO users
		if verificationToken != "" {
			t.Errorf("expected empty verification token for SSO user, got %s", verificationToken)
		}

		// Verify no verification token was created for SSO users
		if len(f.verificationTokenDB.tokens) != 0 {
			t.Errorf("expected 0 verification tokens for SSO user, got %d", len(f.verificationTokenDB.tokens))
		}
	})
}
