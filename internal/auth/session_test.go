package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

// sessionServiceTestFixture holds all dependencies for SessionService tests
type sessionServiceTestFixture struct {
	service       *SessionService
	mfaSettingsDB *mockMFASettingsDB
	rbacService   *mockRBACService
	jwtService    *mockJWTService
}

func newSessionServiceTestFixture() *sessionServiceTestFixture {
	mfaSettingsDB := newMockMFASettingsDB()
	rbacService := newMockRBACService()
	jwtService := newMockJWTService()

	service := NewSessionService(&SessionServiceConfig{
		MFASettingsDB: mfaSettingsDB,
		RBACService:   rbacService,
		JWTService:    jwtService,
		Logger:        &mockLogger{},
	})

	return &sessionServiceTestFixture{
		service:       service,
		mfaSettingsDB: mfaSettingsDB,
		rbacService:   rbacService,
		jwtService:    jwtService,
	}
}

func TestCreateSession_SkipMFACheck(t *testing.T) {
	f := newSessionServiceTestFixture()
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	// Setup: user has scopes
	f.rbacService.userScopes[userID] = []sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate}

	tokens, err := f.service.CreateSession(ctx, tenantID, userID, false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should issue full session tokens
	if tokens.AccessToken == "" {
		t.Error("expected access token to be set")
	}
	if tokens.RefreshToken == "" {
		t.Error("expected refresh token to be set")
	}
	if tokens.MFAChallengeToken != "" {
		t.Error("expected MFA challenge token to be empty")
	}
	if tokens.RequiresMFA {
		t.Error("expected RequiresMFA to be false")
	}
	if tokens.AccessExpiration != time.Hour {
		t.Errorf("expected access expiration to be 1 hour, got %v", tokens.AccessExpiration)
	}
	if tokens.RefreshExpiration != 24*time.Hour {
		t.Errorf("expected refresh expiration to be 24 hours, got %v", tokens.RefreshExpiration)
	}
}

func TestCreateSession_MFANotEnabled(t *testing.T) {
	f := newSessionServiceTestFixture()
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	// Setup: user has scopes, no MFA enabled
	f.rbacService.userScopes[userID] = []sdk.Scope{sdk.ScopeUserRead}
	// mfaSettingsDB returns ErrMFANotEnabled by default (empty map)

	tokens, err := f.service.CreateSession(ctx, tenantID, userID, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should issue full session tokens (MFA not enabled)
	if tokens.AccessToken == "" {
		t.Error("expected access token to be set")
	}
	if tokens.RefreshToken == "" {
		t.Error("expected refresh token to be set")
	}
	if tokens.MFAChallengeToken != "" {
		t.Error("expected MFA challenge token to be empty")
	}
	if tokens.RequiresMFA {
		t.Error("expected RequiresMFA to be false")
	}
}

func TestCreateSession_MFAEnabled(t *testing.T) {
	f := newSessionServiceTestFixture()
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	// Setup: user has MFA enabled
	verifiedAt := time.Now()
	f.mfaSettingsDB.settings[userID] = &MFASettings{
		UserID:     userID,
		VerifiedAt: &verifiedAt,
	}

	tokens, err := f.service.CreateSession(ctx, tenantID, userID, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should issue only MFA challenge token
	if tokens.AccessToken != "" {
		t.Error("expected access token to be empty")
	}
	if tokens.RefreshToken != "" {
		t.Error("expected refresh token to be empty")
	}
	if tokens.MFAChallengeToken == "" {
		t.Error("expected MFA challenge token to be set")
	}
	if !tokens.RequiresMFA {
		t.Error("expected RequiresMFA to be true")
	}
	if tokens.MFAChallengeExpiration != 5*time.Minute {
		t.Errorf("expected MFA challenge expiration to be 5 minutes, got %v", tokens.MFAChallengeExpiration)
	}
}

func TestCreateSession_MFAEnabledButNotVerified(t *testing.T) {
	f := newSessionServiceTestFixture()
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	// Setup: user has MFA settings but not verified (VerifiedAt is nil)
	f.mfaSettingsDB.settings[userID] = &MFASettings{
		UserID:     userID,
		VerifiedAt: nil, // Not verified yet
	}
	f.rbacService.userScopes[userID] = []sdk.Scope{sdk.ScopeUserRead}

	tokens, err := f.service.CreateSession(ctx, tenantID, userID, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should issue full session tokens (MFA not verified)
	if tokens.AccessToken == "" {
		t.Error("expected access token to be set")
	}
	if tokens.RefreshToken == "" {
		t.Error("expected refresh token to be set")
	}
	if tokens.MFAChallengeToken != "" {
		t.Error("expected MFA challenge token to be empty")
	}
	if tokens.RequiresMFA {
		t.Error("expected RequiresMFA to be false")
	}
}

func TestCreateSession_MFASettingsDBError(t *testing.T) {
	f := newSessionServiceTestFixture()
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	// Setup: mock MFA settings DB to return an error
	mockMFADB := &mockMFASettingsDBWithError{
		err: errors.New("database connection failed"),
	}
	f.service.mfaSettingsDB = mockMFADB

	_, err := f.service.CreateSession(ctx, tenantID, userID, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "failed to get MFA settings: database connection failed" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCreateSession_GetUserScopesError(t *testing.T) {
	f := newSessionServiceTestFixture()
	ctx := context.Background()
	tenantID := uuid.New()
	userID := uuid.New()

	// Setup: rbacService returns error
	f.rbacService.getUserScopesError = errors.New("failed to retrieve permissions")

	_, err := f.service.CreateSession(ctx, tenantID, userID, false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "failed to retrieve user scopes: failed to retrieve permissions" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRefreshSession_Success(t *testing.T) {
	f := newSessionServiceTestFixture()
	ctx := context.Background()

	// Setup: Create a specific user ID and set scopes for it
	userID := uuid.New()
	tenantID := uuid.New()
	f.rbacService.userScopes[userID] = []sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate}

	// Replace JWT service with one that returns our specific claims
	f.service.jwtService = &mockJWTServiceWithClaims{
		claims: &jwt.Claims{
			UserID:   userID,
			TenantID: tenantID,
		},
	}

	tokens, err := f.service.RefreshSession(ctx, "valid_refresh_token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should issue new access and refresh tokens
	if tokens.AccessToken == "" {
		t.Error("expected access token to be set")
	}
	if tokens.RefreshToken == "" {
		t.Error("expected refresh token to be set")
	}
	if tokens.MFAChallengeToken != "" {
		t.Error("expected MFA challenge token to be empty")
	}
	if tokens.RequiresMFA {
		t.Error("expected RequiresMFA to be false")
	}
	if tokens.AccessExpiration != time.Hour {
		t.Errorf("expected access expiration to be 1 hour, got %v", tokens.AccessExpiration)
	}
	if tokens.RefreshExpiration != 24*time.Hour {
		t.Errorf("expected refresh expiration to be 24 hours, got %v", tokens.RefreshExpiration)
	}
}

func TestRefreshSession_InvalidToken(t *testing.T) {
	f := newSessionServiceTestFixture()
	ctx := context.Background()

	// Setup: mock JWT service to return validation error
	mockJWT := &mockJWTServiceWithError{
		validateError: errors.New("token expired"),
	}
	f.service.jwtService = mockJWT

	_, err := f.service.RefreshSession(ctx, "expired_token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "invalid or expired refresh token: token expired" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRefreshSession_GetUserScopesError(t *testing.T) {
	f := newSessionServiceTestFixture()
	ctx := context.Background()

	// Setup: rbacService returns error
	f.rbacService.getUserScopesError = errors.New("database error")

	_, err := f.service.RefreshSession(ctx, "valid_token")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "failed to retrieve user scopes: database error" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// Additional mock types for error testing

type mockMFASettingsDBWithError struct {
	err error
}

func (m *mockMFASettingsDBWithError) GetByUserID(ctx context.Context, userID uuid.UUID) (*MFASettings, error) {
	return nil, m.err
}

func (m *mockMFASettingsDBWithError) Delete(ctx context.Context, userID uuid.UUID) error {
	return nil
}

type mockJWTServiceWithError struct {
	validateError error
}

func (m *mockJWTServiceWithError) IssueAccessToken(tenantID, userID uuid.UUID, scopes []sdk.Scope) (string, error) {
	return "mock_access_token", nil
}

func (m *mockJWTServiceWithError) IssueMFAChallengeToken(tenantID, userID uuid.UUID) (string, error) {
	return "mock_mfa_challenge_token", nil
}

func (m *mockJWTServiceWithError) IssueRefreshToken(tenantID, userID uuid.UUID) (string, error) {
	return "mock_refresh_token", nil
}

func (m *mockJWTServiceWithError) ValidateToken(token string) (*jwt.Claims, error) {
	if m.validateError != nil {
		return nil, m.validateError
	}
	return &jwt.Claims{
		UserID:   uuid.New(),
		TenantID: uuid.New(),
	}, nil
}

func (m *mockJWTServiceWithError) GetAccessTokenExpiration() time.Duration {
	return time.Hour
}

func (m *mockJWTServiceWithError) GetRefreshTokenExpiration() time.Duration {
	return 24 * time.Hour
}

func (m *mockJWTServiceWithError) GetMFAChallengeTokenExpiration() time.Duration {
	return 5 * time.Minute
}

type mockJWTServiceWithClaims struct {
	claims *jwt.Claims
}

func (m *mockJWTServiceWithClaims) IssueAccessToken(tenantID, userID uuid.UUID, scopes []sdk.Scope) (string, error) {
	return "mock_access_token", nil
}

func (m *mockJWTServiceWithClaims) IssueMFAChallengeToken(tenantID, userID uuid.UUID) (string, error) {
	return "mock_mfa_challenge_token", nil
}

func (m *mockJWTServiceWithClaims) IssueRefreshToken(tenantID, userID uuid.UUID) (string, error) {
	return "mock_refresh_token", nil
}

func (m *mockJWTServiceWithClaims) ValidateToken(token string) (*jwt.Claims, error) {
	return m.claims, nil
}

func (m *mockJWTServiceWithClaims) GetAccessTokenExpiration() time.Duration {
	return time.Hour
}

func (m *mockJWTServiceWithClaims) GetRefreshTokenExpiration() time.Duration {
	return 24 * time.Hour
}

func (m *mockJWTServiceWithClaims) GetMFAChallengeTokenExpiration() time.Duration {
	return 5 * time.Minute
}
