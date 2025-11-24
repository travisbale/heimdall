package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

func TestIssuer_IssueAccessToken(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	userID := uuid.New()
	tenantID := uuid.New()
	scopes := []sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate}

	token, err := service.IssueAccessToken(tenantID, userID, scopes)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if token == "" {
		t.Error("expected non-empty token")
	}

	// Parse token to verify structure
	claims := &Claims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return service.publicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	if !parsedToken.Valid {
		t.Error("expected valid token")
	}

	if claims.Subject != userID.String() {
		t.Errorf("expected subject %s, got %s", userID.String(), claims.Subject)
	}

	if claims.TenantID != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, claims.TenantID)
	}

	if len(claims.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(claims.Scopes))
	}

	if claims.Issuer != "test-issuer" {
		t.Errorf("expected issuer 'test-issuer', got %s", claims.Issuer)
	}
}

func TestIssuer_IssueRefreshToken(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	userID := uuid.New()
	tenantID := uuid.New()

	token, err := service.IssueRefreshToken(tenantID, userID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if token == "" {
		t.Error("expected non-empty token")
	}

	// Parse token to verify it has no permissions
	claims := &Claims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return service.publicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	if len(claims.Scopes) != 0 {
		t.Errorf("expected 0 scopes in refresh token, got %d", len(claims.Scopes))
	}
}

func TestIssuer_TokenExpiration(t *testing.T) {
	privateKeyPath, publicKeyPath := generateTestKeys(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	config := &Config{
		Issuer:                 "test-issuer",
		PrivateKeyPath:         privateKeyPath,
		PublicKeyPath:          publicKeyPath,
		AccessTokenExpiration:  1 * time.Second, // Very short expiration for testing
		RefreshTokenExpiration: 24 * time.Hour,
	}

	issuer, err := NewIssuer(config)
	if err != nil {
		t.Fatalf("failed to create issuer: %v", err)
	}

	userID := uuid.New()
	tenantID := uuid.New()

	token, err := issuer.IssueAccessToken(tenantID, userID, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Wait for token to expire
	time.Sleep(2 * time.Second)

	// Parse token to check expiration
	claims := &Claims{}
	validator, _ := NewValidator(publicKeyPath)
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return validator.publicKey, nil
	})

	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestIssuer_GetExpirations(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	accessExp := service.GetAccessTokenExpiration()
	if accessExp != 15*time.Minute {
		t.Errorf("expected access token expiration 15m, got %v", accessExp)
	}

	refreshExp := service.GetRefreshTokenExpiration()
	if refreshExp != 24*time.Hour {
		t.Errorf("expected refresh token expiration 24h, got %v", refreshExp)
	}
}

func TestNewIssuer_InvalidPrivateKeyPath(t *testing.T) {
	config := &Config{
		Issuer:                 "test",
		PrivateKeyPath:         "/nonexistent/path/private.pem",
		PublicKeyPath:          "/tmp/public.pem",
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 24 * time.Hour,
	}

	_, err := NewIssuer(config)
	if err == nil {
		t.Error("expected error for invalid private key path")
	}
}
