package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// Test key generation helpers

func generateTestKeys(t *testing.T) (privateKeyPath, publicKeyPath string) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create temporary files
	privateKeyFile, err := os.CreateTemp("", "jwt_private_*.pem")
	if err != nil {
		t.Fatalf("failed to create temp private key file: %v", err)
	}
	defer privateKeyFile.Close()

	publicKeyFile, err := os.CreateTemp("", "jwt_public_*.pem")
	if err != nil {
		t.Fatalf("failed to create temp public key file: %v", err)
	}
	defer publicKeyFile.Close()

	// Encode private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		t.Fatalf("failed to encode private key: %v", err)
	}

	// Encode public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		t.Fatalf("failed to encode public key: %v", err)
	}

	return privateKeyFile.Name(), publicKeyFile.Name()
}

func cleanupKeys(privateKeyPath, publicKeyPath string) {
	os.Remove(privateKeyPath)
	os.Remove(publicKeyPath)
}

func createTestService(t *testing.T) (*Service, string, string) {
	privateKeyPath, publicKeyPath := generateTestKeys(t)

	config := &Config{
		Issuer:                 "test-issuer",
		PrivateKeyPath:         privateKeyPath,
		PublicKeyPath:          publicKeyPath,
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 24 * time.Hour,
	}

	service, err := NewService(config)
	if err != nil {
		t.Fatalf("failed to create test service: %v", err)
	}

	return service, privateKeyPath, publicKeyPath
}

// Issuer Tests

func TestIssuer_IssueAccessToken(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	userID := uuid.New()
	tenantID := uuid.New()
	scopes := []sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate}

	token, err := service.IssueAccessToken(userID, tenantID, scopes)
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

	token, err := service.IssueRefreshToken(userID, tenantID)
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

	token, err := issuer.IssueAccessToken(userID, tenantID, nil)
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

// Validator Tests

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

// Round-trip Tests

func TestRoundTrip_AccessToken(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	userID := uuid.New()
	tenantID := uuid.New()
	scopes := []sdk.Scope{sdk.ScopeUserRead, sdk.ScopeUserUpdate, sdk.Scope("delete:users")}

	// Issue token
	token, err := service.IssueAccessToken(userID, tenantID, scopes)
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	// Validate token
	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("failed to validate token: %v", err)
	}

	// Verify all fields
	if claims.Subject != userID.String() {
		t.Errorf("subject mismatch: expected %s, got %s", userID.String(), claims.Subject)
	}

	if claims.TenantID != tenantID {
		t.Errorf("tenant ID mismatch: expected %s, got %s", tenantID, claims.TenantID)
	}

	if len(claims.Scopes) != 3 {
		t.Errorf("scopes count mismatch: expected 3, got %d", len(claims.Scopes))
	}

	for i, scope := range scopes {
		if claims.Scopes[i] != scope {
			t.Errorf("scope mismatch at index %d: expected %s, got %s", i, scope, claims.Scopes[i])
		}
	}
}

func TestRoundTrip_RefreshToken(t *testing.T) {
	service, privateKeyPath, publicKeyPath := createTestService(t)
	defer cleanupKeys(privateKeyPath, publicKeyPath)

	userID := uuid.New()
	tenantID := uuid.New()

	// Issue refresh token
	token, err := service.IssueRefreshToken(userID, tenantID)
	if err != nil {
		t.Fatalf("failed to issue refresh token: %v", err)
	}

	// Validate token
	claims, err := service.ValidateToken(token)
	if err != nil {
		t.Fatalf("failed to validate refresh token: %v", err)
	}

	// Verify refresh token has no scopes
	if len(claims.Scopes) != 0 {
		t.Errorf("expected no scopes in refresh token, got %d", len(claims.Scopes))
	}
}

// Error Cases

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

func TestNewValidator_InvalidPublicKeyPath(t *testing.T) {
	_, err := NewValidator("/nonexistent/path/public.pem")
	if err == nil {
		t.Error("expected error for invalid public key path")
	}
}

func TestNewService_InvalidPrivateKey(t *testing.T) {
	config := &Config{
		Issuer:                 "test",
		PrivateKeyPath:         "/nonexistent/private.pem",
		PublicKeyPath:          "/tmp/public.pem",
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 24 * time.Hour,
	}

	_, err := NewService(config)
	if err == nil {
		t.Error("expected error for invalid private key path")
	}
}
