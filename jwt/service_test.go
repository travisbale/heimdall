package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// Test helpers - shared across issuer and validator tests

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

// Round-trip tests - testing issuer and validator together

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
