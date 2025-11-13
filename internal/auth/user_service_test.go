package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Mock implementations for UserService testing

type mockHasher struct {
	hashResult  string
	hashError   error
	verifyError error
}

func (m *mockHasher) HashPassword(password string) (string, error) {
	if m.hashError != nil {
		return "", m.hashError
	}
	if m.hashResult != "" {
		return m.hashResult, nil
	}
	return "hashed_" + password, nil
}

func (m *mockHasher) VerifyPassword(password, encodedHash string) error {
	if m.verifyError != nil {
		return m.verifyError
	}
	// Simple mock verification - check if hash matches "hashed_" + password
	if encodedHash == "hashed_"+password {
		return nil
	}
	return ErrInvalidCredentials
}

type mockEmailService struct {
	verificationEmailError  error
	passwordResetEmailError error
	verificationEmails      []string
	passwordResetEmails     []string
}

func (m *mockEmailService) SendVerificationEmail(ctx context.Context, email, token string) error {
	if m.verificationEmailError != nil {
		return m.verificationEmailError
	}
	m.verificationEmails = append(m.verificationEmails, email)
	return nil
}

func (m *mockEmailService) SendPasswordResetEmail(ctx context.Context, email, token string) error {
	if m.passwordResetEmailError != nil {
		return m.passwordResetEmailError
	}
	m.passwordResetEmails = append(m.passwordResetEmails, email)
	return nil
}

type mockTokenDB struct {
	tokens      map[string]*Token
	createError error
	getError    error
	deleteError error
}

func newMockTokenDB() *mockTokenDB {
	return &mockTokenDB{
		tokens: make(map[string]*Token),
	}
}

func (m *mockTokenDB) CreateToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*Token, error) {
	if m.createError != nil {
		return nil, m.createError
	}
	t := &Token{
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
	}
	m.tokens[token] = t
	return t, nil
}

func (m *mockTokenDB) GetToken(ctx context.Context, token string) (*Token, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	t, ok := m.tokens[token]
	if !ok {
		return nil, ErrVerificationTokenNotFound
	}
	return t, nil
}

func (m *mockTokenDB) DeleteToken(ctx context.Context, userID uuid.UUID) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	for token, t := range m.tokens {
		if t.UserID == userID {
			delete(m.tokens, token)
			return nil
		}
	}
	return nil
}

type mockLoginAttemptsService struct {
	locked             bool
	lockedUntil        time.Time
	lockError          error
	recordFailedError  error
	recordSuccessError error
	failedAttempts     []string
	successfulAttempts []string
}

func (m *mockLoginAttemptsService) IsAccountLocked(ctx context.Context, email string) (bool, time.Time, error) {
	if m.lockError != nil {
		return false, time.Time{}, m.lockError
	}
	return m.locked, m.lockedUntil, nil
}

func (m *mockLoginAttemptsService) RecordFailedLogin(ctx context.Context, email string, userID *uuid.UUID, ipAddress *string, lastLoginAt *time.Time) error {
	if m.recordFailedError != nil {
		return m.recordFailedError
	}
	m.failedAttempts = append(m.failedAttempts, email)
	return nil
}

func (m *mockLoginAttemptsService) RecordSuccessfulLogin(ctx context.Context, email string, userID *uuid.UUID, ipAddress *string) error {
	if m.recordSuccessError != nil {
		return m.recordSuccessError
	}
	m.successfulAttempts = append(m.successfulAttempts, email)
	return nil
}

type mockOIDCServiceForUser struct {
	ssoRequired bool
	ssoError    error
}

func (m *mockOIDCServiceForUser) IsSSORequired(ctx context.Context, email string) (bool, error) {
	if m.ssoError != nil {
		return false, m.ssoError
	}
	return m.ssoRequired, nil
}

// Helper function to add a user to mockUserDB (adds to both maps)
func addUserToMockDB(userDB *mockUserDB, user *User) {
	userDB.users[user.ID] = user
	userDB.emails[user.Email] = user
}

// Helper function to create a test UserService with mocks
func createTestUserService() (*UserService, *mockUserDB, *mockHasher, *mockEmailService, *mockTokenDB, *mockTokenDB, *mockLoginAttemptsService, *mockOIDCServiceForUser) {
	userDB := newMockUserDB()
	hasher := &mockHasher{}
	emailService := &mockEmailService{}
	verificationTokenDB := newMockTokenDB()
	passwordResetTokenDB := newMockTokenDB()
	loginAttemptsService := &mockLoginAttemptsService{}
	oidcService := &mockOIDCServiceForUser{}
	logger := &mockLogger{}

	service := NewUserService(&UserServiceConfig{
		UserDB:               userDB,
		Hasher:               hasher,
		EmailService:         emailService,
		VerificationTokenDB:  verificationTokenDB,
		PasswordResetTokenDB: passwordResetTokenDB,
		LoginAttemptsService: loginAttemptsService,
		OIDCService:          oidcService,
		Logger:               logger,
	})

	return service, userDB, hasher, emailService, verificationTokenDB, passwordResetTokenDB, loginAttemptsService, oidcService
}

// Register Tests

func TestRegister_Success_NewUser(t *testing.T) {
	service, userDB, _, emailService, tokenDB, _, _, _ := createTestUserService()
	ctx := context.Background()

	user, err := service.Register(ctx, "newuser@example.com")
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
	if len(userDB.users) != 1 {
		t.Errorf("expected 1 user in DB, got %d", len(userDB.users))
	}

	// Verify verification token was created
	if len(tokenDB.tokens) != 1 {
		t.Errorf("expected 1 token in DB, got %d", len(tokenDB.tokens))
	}

	// Verify verification email was sent
	if len(emailService.verificationEmails) != 1 {
		t.Errorf("expected 1 verification email sent, got %d", len(emailService.verificationEmails))
	}
}

func TestRegister_Success_ExistingUnverifiedUser(t *testing.T) {
	service, userDB, _, emailService, tokenDB, _, _, _ := createTestUserService()
	ctx := context.Background()

	// Create existing unverified user
	tenantID := uuid.New()
	existingUser := &User{
		ID:       uuid.New(),
		TenantID: tenantID,
		Email:    "existing@example.com",
		Status:   UserStatusUnverified,
	}
	addUserToMockDB(userDB, existingUser)

	// Register again with same email
	user, err := service.Register(ctx, "existing@example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if user.ID != existingUser.ID {
		t.Errorf("expected to reuse existing user")
	}

	// Verify new verification token was created
	if len(tokenDB.tokens) != 1 {
		t.Errorf("expected 1 token in DB, got %d", len(tokenDB.tokens))
	}

	// Verify verification email was sent
	if len(emailService.verificationEmails) != 1 {
		t.Errorf("expected 1 verification email sent, got %d", len(emailService.verificationEmails))
	}
}

func TestRegister_SSORequired(t *testing.T) {
	service, _, _, _, _, _, _, oidcService := createTestUserService()
	ctx := context.Background()

	oidcService.ssoRequired = true

	_, err := service.Register(ctx, "user@company.com")
	if !errors.Is(err, ErrSSORequired) {
		t.Errorf("expected ErrSSORequired, got %v", err)
	}
}

func TestRegister_DuplicateEmail_ActiveUser(t *testing.T) {
	service, userDB, _, _, _, _, _, _ := createTestUserService()
	ctx := context.Background()

	// Create existing active user
	tenantID := uuid.New()
	existingUser := &User{
		ID:       uuid.New(),
		TenantID: tenantID,
		Email:    "active@example.com",
		Status:   UserStatusActive,
	}
	addUserToMockDB(userDB, existingUser)

	_, err := service.Register(ctx, "active@example.com")
	if !errors.Is(err, ErrDuplicateEmail) {
		t.Errorf("expected ErrDuplicateEmail, got %v", err)
	}
}

// ConfirmRegistration Tests

func TestConfirmRegistration_Success(t *testing.T) {
	service, userDB, _, _, tokenDB, _, _, _ := createTestUserService()
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
	addUserToMockDB(userDB, user)

	// Create verification token
	token := "verification_token_123"
	tokenDB.tokens[token] = &Token{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	confirmedUser, err := service.ConfirmRegistration(ctx, token, "newpassword123")
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
	if len(tokenDB.tokens) != 0 {
		t.Errorf("expected token to be deleted, got %d tokens", len(tokenDB.tokens))
	}
}

func TestConfirmRegistration_ExpiredToken(t *testing.T) {
	service, userDB, _, _, tokenDB, _, _, _ := createTestUserService()
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
	addUserToMockDB(userDB, user)

	// Create expired verification token
	token := "expired_token"
	tokenDB.tokens[token] = &Token{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	}

	_, err := service.ConfirmRegistration(ctx, token, "newpassword123")
	if !errors.Is(err, ErrVerificationTokenNotFound) {
		t.Errorf("expected ErrVerificationTokenNotFound, got %v", err)
	}
}

func TestConfirmRegistration_AlreadyVerified(t *testing.T) {
	service, userDB, _, _, tokenDB, _, _, _ := createTestUserService()
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
	addUserToMockDB(userDB, user)

	// Create verification token
	token := "valid_token"
	tokenDB.tokens[token] = &Token{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	_, err := service.ConfirmRegistration(ctx, token, "newpassword123")
	if !errors.Is(err, ErrAccountAlreadyVerified) {
		t.Errorf("expected ErrAccountAlreadyVerified, got %v", err)
	}
}

func TestConfirmRegistration_InvalidToken(t *testing.T) {
	service, _, _, _, _, _, _, _ := createTestUserService()
	ctx := context.Background()

	_, err := service.ConfirmRegistration(ctx, "nonexistent_token", "password123")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

// CreateUser Tests

func TestCreateUser_Success(t *testing.T) {
	service, userDB, _, _, _, _, _, _ := createTestUserService()
	ctx := context.Background()

	tenantID := uuid.New()
	user, tempPassword, err := service.CreateUser(ctx, tenantID, "admin@example.com")
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
	if len(userDB.users) != 1 {
		t.Errorf("expected 1 user in DB, got %d", len(userDB.users))
	}
}

// Login Tests

func TestLogin_Success(t *testing.T) {
	service, userDB, _, _, _, _, loginAttempts, _ := createTestUserService()
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
	addUserToMockDB(userDB, user)

	loggedInUser, err := service.Login(ctx, "login@example.com", "correctpassword", "192.168.1.1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if loggedInUser.ID != userID {
		t.Error("expected to return the correct user")
	}

	// Verify successful login was recorded
	if len(loginAttempts.successfulAttempts) != 1 {
		t.Errorf("expected 1 successful attempt recorded, got %d", len(loginAttempts.successfulAttempts))
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	service, userDB, _, _, _, _, loginAttempts, _ := createTestUserService()
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
	addUserToMockDB(userDB, user)

	_, err := service.Login(ctx, "login@example.com", "wrongpassword", "192.168.1.1")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}

	// Verify failed login was recorded
	if len(loginAttempts.failedAttempts) != 1 {
		t.Errorf("expected 1 failed attempt recorded, got %d", len(loginAttempts.failedAttempts))
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	service, _, _, _, _, _, loginAttempts, _ := createTestUserService()
	ctx := context.Background()

	_, err := service.Login(ctx, "nonexistent@example.com", "password", "192.168.1.1")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}

	// Verify failed login was recorded
	if len(loginAttempts.failedAttempts) != 1 {
		t.Errorf("expected 1 failed attempt recorded, got %d", len(loginAttempts.failedAttempts))
	}
}

func TestLogin_AccountLocked(t *testing.T) {
	service, _, _, _, _, _, loginAttempts, _ := createTestUserService()
	ctx := context.Background()

	loginAttempts.locked = true
	loginAttempts.lockedUntil = time.Now().Add(30 * time.Minute)

	_, err := service.Login(ctx, "locked@example.com", "password", "192.168.1.1")
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}
}

func TestLogin_UnverifiedEmail(t *testing.T) {
	service, userDB, _, _, _, _, _, _ := createTestUserService()
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
	addUserToMockDB(userDB, user)

	_, err := service.Login(ctx, "unverified@example.com", "password", "192.168.1.1")
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Errorf("expected ErrEmailNotVerified, got %v", err)
	}
}

// Password Reset Tests

func TestInitiatePasswordReset_Success(t *testing.T) {
	service, userDB, _, emailService, _, passwordResetTokenDB, _, _ := createTestUserService()
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
	addUserToMockDB(userDB, user)

	err := service.InitiatePasswordReset(ctx, "reset@example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify reset token was created
	if len(passwordResetTokenDB.tokens) != 1 {
		t.Errorf("expected 1 reset token in DB, got %d", len(passwordResetTokenDB.tokens))
	}

	// Verify password reset email was sent
	if len(emailService.passwordResetEmails) != 1 {
		t.Errorf("expected 1 password reset email sent, got %d", len(emailService.passwordResetEmails))
	}
}

func TestInitiatePasswordReset_UserNotFound(t *testing.T) {
	service, _, _, _, _, _, _, _ := createTestUserService()
	ctx := context.Background()

	err := service.InitiatePasswordReset(ctx, "nonexistent@example.com")
	if err == nil {
		t.Error("expected error for non-existent user")
	}
}

func TestResetPassword_Success(t *testing.T) {
	service, userDB, _, _, _, passwordResetTokenDB, _, _ := createTestUserService()
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
	addUserToMockDB(userDB, user)

	// Create password reset token
	token := "reset_token_123"
	passwordResetTokenDB.tokens[token] = &Token{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := service.ResetPassword(ctx, token, "newpassword123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify password was updated
	updatedUser := userDB.users[userID]
	if updatedUser.PasswordHash == "old_hash" {
		t.Error("expected password hash to be updated")
	}

	// Verify reset token was deleted
	if len(passwordResetTokenDB.tokens) != 0 {
		t.Errorf("expected reset token to be deleted, got %d tokens", len(passwordResetTokenDB.tokens))
	}
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	service, userDB, _, _, _, passwordResetTokenDB, _, _ := createTestUserService()
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
	addUserToMockDB(userDB, user)

	// Create expired password reset token
	token := "expired_reset_token"
	passwordResetTokenDB.tokens[token] = &Token{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	}

	err := service.ResetPassword(ctx, token, "newpassword123")
	if !errors.Is(err, ErrPasswordResetTokenNotFound) {
		t.Errorf("expected ErrPasswordResetTokenNotFound, got %v", err)
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	service, _, _, _, _, _, _, _ := createTestUserService()
	ctx := context.Background()

	err := service.ResetPassword(ctx, "nonexistent_token", "newpassword123")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

// GetScopes Tests

func TestGetScopes_ReturnsEmpty(t *testing.T) {
	service, _, _, _, _, _, _, _ := createTestUserService()
	ctx := context.Background()

	scopes, err := service.GetScopes(ctx, uuid.New())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(scopes) != 0 {
		t.Errorf("expected empty scopes, got %d", len(scopes))
	}
}
