package iam

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	cryptotoken "github.com/travisbale/knowhere/crypto/token"
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
		PasswordValidator:    &stubStrength{},
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

	t.Run("Suspended", func(t *testing.T) {
		f := newPasswordServiceTestFixture()
		ctx := context.Background()

		addUserToMockDB(f.userDB, &User{
			ID:           uuid.New(),
			TenantID:     uuid.New(),
			Email:        "suspended@example.com",
			PasswordHash: "hashed_password",
			Status:       UserStatusSuspended,
		})

		_, err := f.service.VerifyCredentials(ctx, "suspended@example.com", "password")
		if !errors.Is(err, ErrAccountIsInactive) {
			t.Errorf("expected ErrAccountIsInactive, got %v", err)
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
		f.passwordResetTokenDB.tokens[cryptotoken.Hash(token)] = &UserToken{
			UserID:    userID,
			Token:     cryptotoken.Hash(token),
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
		f.passwordResetTokenDB.tokens[cryptotoken.Hash(token)] = &UserToken{
			UserID:    userID,
			Token:     cryptotoken.Hash(token),
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

// A leaked database — a backup, a replica, a stray dump — must not yield working reset
// tokens. Refresh and device tokens are already stored hashed; these are the same class
// of bearer credential.
func TestInitiatePasswordReset_StoresTheTokenHashed(t *testing.T) {
	f := newPasswordServiceTestFixture()
	ctx := context.Background()

	userID := uuid.New()
	addUserToMockDB(f.userDB, &User{
		ID: userID, TenantID: uuid.New(), Email: "reset@example.com", Status: UserStatusActive,
	})

	if err := f.service.InitiatePasswordReset(ctx, "reset@example.com"); err != nil {
		t.Fatalf("InitiatePasswordReset: %v", err)
	}

	if len(f.emailClient.passwordResetTokensSent) != 1 {
		t.Fatalf("want 1 token emailed, got %d", len(f.emailClient.passwordResetTokensSent))
	}
	emailed := f.emailClient.passwordResetTokensSent[0]

	for stored := range f.passwordResetTokenDB.tokens {
		if stored == emailed {
			t.Error("the reset token is stored verbatim; anyone who can read the table can reset any password")
		}
	}
}

// The user only ever has the plaintext token from their email, so the lookup has to hash
// what it is given.
func TestResetPassword_AcceptsTheTokenFromTheEmail(t *testing.T) {
	f := newPasswordServiceTestFixture()
	ctx := context.Background()

	userID := uuid.New()
	addUserToMockDB(f.userDB, &User{
		ID: userID, TenantID: uuid.New(), Email: "reset@example.com",
		PasswordHash: "old_hash", Status: UserStatusActive,
	})
	if err := f.service.InitiatePasswordReset(ctx, "reset@example.com"); err != nil {
		t.Fatalf("InitiatePasswordReset: %v", err)
	}
	emailed := f.emailClient.passwordResetTokensSent[0]

	if err := f.service.ResetPassword(ctx, emailed, "newpassword123"); err != nil {
		t.Fatalf("ResetPassword with the emailed token: %v", err)
	}
	if f.userDB.users[userID].PasswordHash == "old_hash" {
		t.Error("password was not updated")
	}
}

// mockSessionRevoker records whose sessions were signed out.
type mockSessionRevoker struct {
	revoked []uuid.UUID
	err     error
}

func (m *mockSessionRevoker) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	if m.err != nil {
		return m.err
	}
	m.revoked = append(m.revoked, userID)
	return nil
}

// Resetting a password is what someone does when their account is compromised, so it has
// to end the attacker's sessions. Refresh tokens outlive the old password otherwise.
func TestResetPassword_RevokesExistingSessions(t *testing.T) {
	f := newPasswordServiceTestFixture()
	revoker := &mockSessionRevoker{}
	f.service.SessionRevoker = revoker
	ctx := context.Background()

	userID := uuid.New()
	addUserToMockDB(f.userDB, &User{
		ID: userID, TenantID: uuid.New(), Email: "reset@example.com",
		PasswordHash: "old_hash", Status: UserStatusActive,
	})
	if err := f.service.InitiatePasswordReset(ctx, "reset@example.com"); err != nil {
		t.Fatalf("InitiatePasswordReset: %v", err)
	}

	if err := f.service.ResetPassword(ctx, f.emailClient.passwordResetTokensSent[0], "newpassword123"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	if len(revoker.revoked) != 1 || revoker.revoked[0] != userID {
		t.Errorf("sessions revoked = %v, want [%v]", revoker.revoked, userID)
	}
}

// Changing a password deliberately (rather than via reset) should sign other sessions out
// for the same reason.
func TestChangePassword_RevokesExistingSessions(t *testing.T) {
	f := newPasswordServiceTestFixture()
	revoker := &mockSessionRevoker{}
	f.service.SessionRevoker = revoker
	ctx := context.Background()

	userID := uuid.New()
	addUserToMockDB(f.userDB, &User{
		ID: userID, TenantID: uuid.New(), Email: "change@example.com",
		PasswordHash: "hashed_correctpassword", Status: UserStatusActive,
	})

	if err := f.service.ChangePassword(ctx, userID, "correctpassword", "newpassword123"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if len(revoker.revoked) != 1 || revoker.revoked[0] != userID {
		t.Errorf("sessions revoked = %v, want [%v]", revoker.revoked, userID)
	}
}

func TestResetPassword_RejectsAWeakPasswordBeforeWritingIt(t *testing.T) {
	f := newPasswordServiceTestFixture()
	strength := &stubStrength{rejectIt: true}
	f.service.PasswordValidator = strength

	// Hasher rigged to error, so errWeak coming back proves the refusal came first.
	f.hasher.hashError = errors.New("hasher should not have been reached")

	err := f.service.ResetPassword(context.Background(), "any-token", "hunter2hunter2")

	if !errors.Is(err, errWeak) {
		t.Fatalf("want the strength error surfaced, got %v", err)
	}
	if strength.called != 1 {
		t.Errorf("want the check run once, ran %d times", strength.called)
	}
}

func TestChangePassword_RejectsAWeakPassword(t *testing.T) {
	f := newPasswordServiceTestFixture()
	strength := &stubStrength{rejectIt: true}
	f.service.PasswordValidator = strength

	err := f.service.ChangePassword(context.Background(), uuid.New(), "old-password", "hunter2hunter2")

	if !errors.Is(err, errWeak) {
		t.Fatalf("want the strength error surfaced, got %v", err)
	}
	if strength.called != 1 {
		t.Errorf("want the check run once, ran %d times", strength.called)
	}
}

func TestVerifyEmailAndSetPassword_RejectsAWeakPassword(t *testing.T) {
	strength := &stubStrength{rejectIt: true}
	svc := &UserService{
		UserDB:              newMockUserDB(),
		PasswordValidator:   strength,
		Hasher:              &mockHasher{},
		VerificationTokenDB: newMockTokenDB(),
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	_, err := svc.VerifyEmailAndSetPassword(context.Background(), "any-token", "hunter2hunter2")

	if !errors.Is(err, errWeak) {
		t.Fatalf("want the strength error surfaced, got %v", err)
	}
	if strength.called != 1 {
		t.Errorf("want the check run once, ran %d times", strength.called)
	}
}
