package iam

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
)

type passwordServiceTestFixture struct {
	service              *PasswordService
	userDB               *mockUserDB
	hasher               *mockHasher
	emailClient          *mockEmailClient
	passwordResetTokenDB *mockTokenDB
	loginAttempts        *mockLoginAttemptsService
}

func newPasswordServiceTestFixture() *passwordServiceTestFixture {
	userDB := newMockUserDB()
	hasher := &mockHasher{}
	emailClient := &mockEmailClient{}
	passwordResetTokenDB := newMockTokenDB()
	loginAttempts := &mockLoginAttemptsService{}

	service := &PasswordService{
		UserDB:               userDB,
		Hasher:               hasher,
		PasswordResetTokenDB: passwordResetTokenDB,
		EmailClient:          emailClient,
		LoginAttemptsService: loginAttempts,
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	return &passwordServiceTestFixture{
		service:              service,
		userDB:               userDB,
		hasher:               hasher,
		emailClient:          emailClient,
		passwordResetTokenDB: passwordResetTokenDB,
		loginAttempts:        loginAttempts,
	}
}

func TestLogin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f := newPasswordServiceTestFixture()
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

		loggedInUser, err := f.service.VerifyCredentials(ctx, "login@example.com", "correctpassword")
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
		f := newPasswordServiceTestFixture()
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

		_, err := f.service.VerifyCredentials(ctx, "login@example.com", "wrongpassword")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}

		// Verify failed login was recorded
		if len(f.loginAttempts.failedAttempts) != 1 {
			t.Errorf("expected 1 failed attempt recorded, got %d", len(f.loginAttempts.failedAttempts))
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		f := newPasswordServiceTestFixture()
		ctx := context.Background()

		_, err := f.service.VerifyCredentials(ctx, "nonexistent@example.com", "password")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}

		// Verify failed login was recorded
		if len(f.loginAttempts.failedAttempts) != 1 {
			t.Errorf("expected 1 failed attempt recorded, got %d", len(f.loginAttempts.failedAttempts))
		}
	})

	t.Run("AccountLocked", func(t *testing.T) {
		f := newPasswordServiceTestFixture()
		ctx := context.Background()

		f.loginAttempts.locked = true
		f.loginAttempts.lockedUntil = time.Now().Add(30 * time.Minute)

		_, err := f.service.VerifyCredentials(ctx, "locked@example.com", "password")
		if !errors.Is(err, ErrAccountLocked) {
			t.Errorf("expected ErrAccountLocked, got %v", err)
		}
	})

	t.Run("UnverifiedEmail", func(t *testing.T) {
		f := newPasswordServiceTestFixture()
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

		_, err := f.service.VerifyCredentials(ctx, "unverified@example.com", "password")
		if !errors.Is(err, ErrEmailNotVerified) {
			t.Errorf("expected ErrEmailNotVerified, got %v", err)
		}
	})
}

func TestInitiatePasswordReset(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f := newPasswordServiceTestFixture()
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
		if len(f.emailClient.passwordResetEmails) != 1 {
			t.Errorf("expected 1 password reset email sent, got %d", len(f.emailClient.passwordResetEmails))
		}
	})

	t.Run("UserNotFound", func(t *testing.T) {
		f := newPasswordServiceTestFixture()
		ctx := context.Background()

		err := f.service.InitiatePasswordReset(ctx, "nonexistent@example.com")
		if err == nil {
			t.Error("expected error for non-existent user")
		}
	})
}

func TestResetPassword(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f := newPasswordServiceTestFixture()
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
		f := newPasswordServiceTestFixture()
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
		f := newPasswordServiceTestFixture()
		ctx := context.Background()

		err := f.service.ResetPassword(ctx, "nonexistent_token", "newpassword123")
		if err == nil {
			t.Error("expected error for invalid token")
		}
	})
}
