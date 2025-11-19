package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

func TestValidator_ValidateToken_Success(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	userID := uuid.New()
	tenantID := uuid.New()
	scopes := []sdk.Scope{sdk.ScopeUserRead}

	token, err := service.IssueAccessToken(userID, tenantID, scopes)
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if claims.Subject != userID.String() {
		t.Errorf("expected subject %s, got %s", userID.String(), claims.Subject)
	}

	if claims.TenantID != tenantID {
		t.Errorf("expected tenant ID %s, got %s", tenantID, claims.TenantID)
	}

	if len(claims.Scopes) != 1 || claims.Scopes[0] != sdk.ScopeUserRead {
		t.Errorf("expected scopes [user:read], got %v", claims.Scopes)
	}
}

func TestValidator_ValidateToken_ExpiredToken(t *testing.T) {
	privateKeyPath, publicKeyPath := generateTestKeys(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	config := &Config{
		Issuer:                 "test-issuer",
		PrivateKeyPath:         privateKeyPath,
		PublicKeyPath:          publicKeyPath,
		AccessTokenExpiration:  1 * time.Millisecond, // Expire immediately
		RefreshTokenExpiration: 24 * time.Hour,
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	userID := uuid.New()
	tenantID := uuid.New()

	token, err := service.IssueAccessToken(userID, tenantID, nil)
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	_, err = service.ValidateToken(token)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestValidator_ValidateToken_InvalidSignature(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	// Create a token with different keys
	otherPrivateKeyPath, otherPublicKeyPath := generateTestKeys(t)
	defer cleanupKeys(otherPrivateKeyPath, otherPublicKeyPath)

	otherConfig := &Config{
		Issuer:                 "other-issuer",
		PrivateKeyPath:         otherPrivateKeyPath,
		PublicKeyPath:          otherPublicKeyPath,
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 24 * time.Hour,
	}

	otherIssuer, err := NewIssuer(otherConfig)
	if err != nil {
		t.Fatalf("failed to create other issuer: %v", err)
	}

	userID := uuid.New()
	tenantID := uuid.New()

	token, err := otherIssuer.IssueAccessToken(userID, tenantID, nil)
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	// Try to validate with original service (different public key)
	_, err = service.ValidateToken(token)
	if err == nil {
		t.Error("expected error for token signed with different key")
	}
}

func TestValidator_ValidateToken_MalformedToken(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	invalidTokens := []string{
		"",
		"not.a.token",
		"invalid",
		"a.b", // Too few parts
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
	}

	for _, token := range invalidTokens {
		_, err := service.ValidateToken(token)
		if err == nil {
			t.Errorf("expected error for malformed token: %s", token)
		}
	}
}

func TestValidator_ValidateToken_MissingSubject(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	// Manually create a token without subject
	claims := &Claims{
		TenantID: uuid.New(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			// Subject intentionally missing
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(service.privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = service.ValidateToken(signedToken)
	if err != ErrMissingClaims {
		t.Errorf("expected ErrMissingClaims, got %v", err)
	}
}

func TestValidator_ValidateToken_MissingTenantID(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	// Manually create a token without tenant ID
	claims := &Claims{
		TenantID: uuid.Nil, // Missing tenant ID
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   uuid.New().String(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(service.privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = service.ValidateToken(signedToken)
	if err != ErrMissingClaims {
		t.Errorf("expected ErrMissingClaims, got %v", err)
	}
}

func TestValidator_ValidateToken_WrongAlgorithm(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	// Create a token with HMAC instead of RSA
	claims := &Claims{
		TenantID: uuid.New(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   uuid.New().String(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // Wrong algorithm
	signedToken, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = service.ValidateToken(signedToken)
	if err == nil {
		t.Error("expected error for token with wrong signing algorithm")
	}
}

func TestNewValidator_InvalidPublicKeyPath(t *testing.T) {
	_, err := NewValidator("/nonexistent/path/public.pem")
	if err == nil {
		t.Error("expected error for invalid public key path")
	}
}
