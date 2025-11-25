package iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

// Mocks for AuthService dependencies

type mockPasswordService struct {
	user *User
	err  error
}

func (m *mockPasswordService) VerifyCredentials(ctx context.Context, email, password string) (*User, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

type mockOIDCAuthService struct {
	user *User
	err  error
}

func (m *mockOIDCAuthService) ProcessCallback(ctx context.Context, state, code string) (*User, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

type mockUserAccountService struct {
	user *User
	err  error
}

func (m *mockUserAccountService) VerifyEmailAndSetPassword(ctx context.Context, tokenStr, password string) (*User, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.user, nil
}

type mockMFAVerificationService struct {
	enabled         bool
	isMFAEnabledErr error
	verifyCodeErr   error
}

func (m *mockMFAVerificationService) IsMFAEnabled(ctx context.Context, userID uuid.UUID) (bool, error) {
	if m.isMFAEnabledErr != nil {
		return false, m.isMFAEnabledErr
	}
	return m.enabled, nil
}

func (m *mockMFAVerificationService) VerifyCode(ctx context.Context, userID uuid.UUID, code string) error {
	return m.verifyCodeErr
}

type mockJWTService struct {
	accessToken                 string
	refreshToken                string
	mfaChallengeToken           string
	validateMFAChallengeErr     error
	validateTokenErr            error
	issueAccessTokenErr         error
	issueRefreshTokenErr        error
	issueMFAChallengeTokenErr   error
	mfaChallengeClaims          *jwt.Claims
	refreshClaims               *jwt.Claims
	accessTokenExpiration       time.Duration
	refreshTokenExpiration      time.Duration
	mfaChallengeTokenExpiration time.Duration
}

func newMockJWTService() *mockJWTService {
	return &mockJWTService{
		accessToken:                 "mock_access_token",
		refreshToken:                "mock_refresh_token",
		mfaChallengeToken:           "mock_mfa_challenge_token",
		accessTokenExpiration:       15 * time.Minute,
		refreshTokenExpiration:      24 * time.Hour,
		mfaChallengeTokenExpiration: 5 * time.Minute,
	}
}

func (m *mockJWTService) IssueAccessToken(tenantID, userID uuid.UUID, scopes []sdk.Scope) (string, error) {
	if m.issueAccessTokenErr != nil {
		return "", m.issueAccessTokenErr
	}
	return m.accessToken, nil
}

func (m *mockJWTService) IssueMFAChallengeToken(tenantID, userID uuid.UUID) (string, error) {
	if m.issueMFAChallengeTokenErr != nil {
		return "", m.issueMFAChallengeTokenErr
	}
	return m.mfaChallengeToken, nil
}

func (m *mockJWTService) IssueRefreshToken(tenantID, userID uuid.UUID) (string, error) {
	if m.issueRefreshTokenErr != nil {
		return "", m.issueRefreshTokenErr
	}
	return m.refreshToken, nil
}

func (m *mockJWTService) ValidateMFAChallengeToken(token string) (*jwt.Claims, error) {
	if m.validateMFAChallengeErr != nil {
		return nil, m.validateMFAChallengeErr
	}
	return m.mfaChallengeClaims, nil
}

func (m *mockJWTService) ValidateToken(token string) (*jwt.Claims, error) {
	if m.validateTokenErr != nil {
		return nil, m.validateTokenErr
	}
	return m.refreshClaims, nil
}

func (m *mockJWTService) GetAccessTokenExpiration() time.Duration {
	return m.accessTokenExpiration
}

func (m *mockJWTService) GetRefreshTokenExpiration() time.Duration {
	return m.refreshTokenExpiration
}

func (m *mockJWTService) GetMFAChallengeTokenExpiration() time.Duration {
	return m.mfaChallengeTokenExpiration
}

// Test fixture

type authServiceTestFixture struct {
	service         *AuthService
	passwordService *mockPasswordService
	oidcService     *mockOIDCAuthService
	userService     *mockUserAccountService
	mfaService      *mockMFAVerificationService
	rbacService     *mockRBACService
	jwtService      *mockJWTService
}

func newAuthServiceTestFixture() *authServiceTestFixture {
	passwordService := &mockPasswordService{}
	oidcService := &mockOIDCAuthService{}
	userService := &mockUserAccountService{}
	mfaService := &mockMFAVerificationService{}
	rbacService := newMockRBACService()
	jwtService := newMockJWTService()

	service := NewAuthService(&AuthServiceConfig{
		PasswordService: passwordService,
		OIDCService:     oidcService,
		UserService:     userService,
		MFAService:      mfaService,
		RBACService:     rbacService,
		JWTService:      jwtService,
		Logger:          &mockLogger{},
	})

	return &authServiceTestFixture{
		service:         service,
		passwordService: passwordService,
		oidcService:     oidcService,
		userService:     userService,
		mfaService:      mfaService,
		rbacService:     rbacService,
		jwtService:      jwtService,
	}
}

// Tests

func TestAuthenticateWithPassword(t *testing.T) {
	t.Run("Success_NoMFA", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.passwordService.user = &User{ID: userID, TenantID: tenantID, Email: "user@example.com"}
		// MFA disabled by default (enabled = false)

		tokens, err := f.service.AuthenticateWithPassword(ctx, "user@example.com", "password")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if tokens.RequiresMFA() {
			t.Error("expected RequiresMFA to be false")
		}
		if tokens.AccessToken != "mock_access_token" {
			t.Errorf("expected access token 'mock_access_token', got %s", tokens.AccessToken)
		}
		if tokens.RefreshToken != "mock_refresh_token" {
			t.Errorf("expected refresh token 'mock_refresh_token', got %s", tokens.RefreshToken)
		}
	})

	t.Run("Success_WithMFA", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.passwordService.user = &User{ID: userID, TenantID: tenantID, Email: "user@example.com"}
		f.mfaService.enabled = true

		tokens, err := f.service.AuthenticateWithPassword(ctx, "user@example.com", "password")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !tokens.RequiresMFA() {
			t.Error("expected RequiresMFA to be true")
		}
		if tokens.MFAChallengeToken != "mock_mfa_challenge_token" {
			t.Errorf("expected MFA challenge token, got %s", tokens.MFAChallengeToken)
		}
		if tokens.AccessToken != "" {
			t.Error("expected no access token when MFA is required")
		}
	})

	t.Run("InvalidCredentials", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		f.passwordService.err = ErrInvalidCredentials

		_, err := f.service.AuthenticateWithPassword(ctx, "user@example.com", "wrongpassword")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("MFAStatusCheckError", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.passwordService.user = &User{ID: userID, TenantID: tenantID}
		f.mfaService.isMFAEnabledErr = errors.New("database error")

		_, err := f.service.AuthenticateWithPassword(ctx, "user@example.com", "password")
		if err == nil {
			t.Error("expected error for MFA status check failure")
		}
	})
}

func TestAuthenticateWithOIDC(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.oidcService.user = &User{ID: userID, TenantID: tenantID, Email: "user@example.com"}

		tokens, err := f.service.AuthenticateWithOIDC(ctx, "state", "code")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		// OIDC auth should not require MFA (provider handles it)
		if tokens.RequiresMFA() {
			t.Error("expected RequiresMFA to be false for OIDC")
		}
		if tokens.AccessToken != "mock_access_token" {
			t.Errorf("expected access token, got %s", tokens.AccessToken)
		}
	})

	t.Run("CallbackError", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		f.oidcService.err = errors.New("invalid state")

		_, err := f.service.AuthenticateWithOIDC(ctx, "state", "code")
		if err == nil {
			t.Error("expected error for OIDC callback failure")
		}
	})
}

func TestCompleteRegistration(t *testing.T) {
	t.Run("Success_NoMFA", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.userService.user = &User{ID: userID, TenantID: tenantID, Email: "user@example.com"}
		// MFA disabled by default (enabled = false)

		tokens, err := f.service.CompleteRegistration(ctx, "verification_token", "password")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if tokens.RequiresMFA() {
			t.Error("expected RequiresMFA to be false")
		}
		if tokens.AccessToken == "" {
			t.Error("expected access token to be set")
		}
	})

	t.Run("Success_WithMFA", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.userService.user = &User{ID: userID, TenantID: tenantID, Email: "user@example.com"}
		f.mfaService.enabled = true

		tokens, err := f.service.CompleteRegistration(ctx, "verification_token", "password")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !tokens.RequiresMFA() {
			t.Error("expected RequiresMFA to be true")
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		f.userService.err = ErrVerificationTokenNotFound

		_, err := f.service.CompleteRegistration(ctx, "invalid_token", "password")
		if !errors.Is(err, ErrVerificationTokenNotFound) {
			t.Errorf("expected ErrVerificationTokenNotFound, got %v", err)
		}
	})
}

func TestAuthenticateWithMFA(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.jwtService.mfaChallengeClaims = &jwt.Claims{UserID: userID, TenantID: tenantID}

		tokens, err := f.service.AuthenticateWithMFA(ctx, "challenge_token", "123456")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if tokens.RequiresMFA() {
			t.Error("expected RequiresMFA to be false after MFA verification")
		}
		if tokens.AccessToken == "" {
			t.Error("expected access token to be set")
		}
	})

	t.Run("InvalidChallengeToken", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		f.jwtService.validateMFAChallengeErr = errors.New("invalid token")

		_, err := f.service.AuthenticateWithMFA(ctx, "invalid_challenge", "123456")
		if !errors.Is(err, ErrInvalidChallengeToken) {
			t.Errorf("expected ErrInvalidChallengeToken, got %v", err)
		}
	})

	t.Run("InvalidMFACode", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.jwtService.mfaChallengeClaims = &jwt.Claims{UserID: userID, TenantID: tenantID}
		f.mfaService.verifyCodeErr = ErrInvalidMFACode

		_, err := f.service.AuthenticateWithMFA(ctx, "challenge_token", "wrong_code")
		if !errors.Is(err, ErrInvalidMFACode) {
			t.Errorf("expected ErrInvalidMFACode, got %v", err)
		}
	})
}

func TestRefreshSession(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.jwtService.refreshClaims = &jwt.Claims{UserID: userID, TenantID: tenantID}

		tokens, err := f.service.RefreshSession(ctx, "refresh_token")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if tokens.AccessToken == "" {
			t.Error("expected new access token")
		}
		if tokens.RefreshToken == "" {
			t.Error("expected new refresh token")
		}
	})

	t.Run("InvalidRefreshToken", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		f.jwtService.validateTokenErr = errors.New("expired token")

		_, err := f.service.RefreshSession(ctx, "invalid_refresh_token")
		if err == nil {
			t.Error("expected error for invalid refresh token")
		}
	})
}

func TestCreateSession_Errors(t *testing.T) {
	t.Run("GetUserScopesError", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.passwordService.user = &User{ID: userID, TenantID: tenantID}
		// MFA disabled by default
		f.rbacService.getUserScopesError = errors.New("database error")

		_, err := f.service.AuthenticateWithPassword(ctx, "user@example.com", "password")
		if err == nil {
			t.Error("expected error when getting user scopes fails")
		}
	})

	t.Run("IssueAccessTokenError", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.passwordService.user = &User{ID: userID, TenantID: tenantID}
		// MFA disabled by default
		f.jwtService.issueAccessTokenErr = errors.New("signing error")

		_, err := f.service.AuthenticateWithPassword(ctx, "user@example.com", "password")
		if err == nil {
			t.Error("expected error when issuing access token fails")
		}
	})

	t.Run("IssueRefreshTokenError", func(t *testing.T) {
		f := newAuthServiceTestFixture()
		ctx := context.Background()

		userID := uuid.New()
		tenantID := uuid.New()
		f.passwordService.user = &User{ID: userID, TenantID: tenantID}
		// MFA disabled by default
		f.jwtService.issueRefreshTokenErr = errors.New("signing error")

		_, err := f.service.AuthenticateWithPassword(ctx, "user@example.com", "password")
		if err == nil {
			t.Error("expected error when issuing refresh token fails")
		}
	})
}

func TestIssueMFAChallenge_Error(t *testing.T) {
	f := newAuthServiceTestFixture()
	ctx := context.Background()

	userID := uuid.New()
	tenantID := uuid.New()
	f.passwordService.user = &User{ID: userID, TenantID: tenantID}
	f.mfaService.enabled = true
	f.jwtService.issueMFAChallengeTokenErr = errors.New("signing error")

	_, err := f.service.AuthenticateWithPassword(ctx, "user@example.com", "password")
	if err == nil {
		t.Error("expected error when issuing MFA challenge token fails")
	}
}
