package argon2

import (
	"strings"
	"testing"

	"github.com/travisbale/heimdall/internal/auth"
)

func createTestHasher() *Hasher {
	return NewHasher(&Config{
		Memory:      64 * 1024, // 64 MB
		Iterations:  1,
		SaltLength:  16,
		KeyLength:   32,
		Parallelism: 4,
	})
}

// HashPassword Tests

func TestHashPassword_Success(t *testing.T) {
	hasher := createTestHasher()

	password := "mySecurePassword123!"
	hash, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if hash == "" {
		t.Error("expected non-empty hash")
	}

	// Verify hash format: $argon2id$v=19$m=X,t=Y,p=Z$salt$hash
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("expected hash to start with $argon2id$, got %s", hash)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("expected 6 parts in hash, got %d", len(parts))
	}
}

func TestHashPassword_DifferentSalts(t *testing.T) {
	hasher := createTestHasher()

	password := "samePassword"

	hash1, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password (1): %v", err)
	}

	hash2, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password (2): %v", err)
	}

	// Same password should produce different hashes due to different salts
	if hash1 == hash2 {
		t.Error("expected different hashes for same password (different salts)")
	}
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	hasher := createTestHasher()

	hash, err := hasher.HashPassword("")
	if err != nil {
		t.Fatalf("expected no error for empty password, got %v", err)
	}

	if hash == "" {
		t.Error("expected non-empty hash even for empty password")
	}
}

func TestHashPassword_LongPassword(t *testing.T) {
	hasher := createTestHasher()

	// Test with a very long password
	longPassword := strings.Repeat("a", 1000)
	hash, err := hasher.HashPassword(longPassword)
	if err != nil {
		t.Fatalf("expected no error for long password, got %v", err)
	}

	if hash == "" {
		t.Error("expected non-empty hash")
	}
}

func TestHashPassword_SpecialCharacters(t *testing.T) {
	hasher := createTestHasher()

	passwords := []string{
		"pass!@#$%^&*()",
		"pāsswørd",
		"密码",
		"🔐secure🔑",
	}

	for _, password := range passwords {
		hash, err := hasher.HashPassword(password)
		if err != nil {
			t.Errorf("password %q: unexpected error: %v", password, err)
		}
		if hash == "" {
			t.Errorf("password %q: expected non-empty hash", password)
		}
	}
}

// VerifyPassword Tests

func TestVerifyPassword_Success(t *testing.T) {
	hasher := createTestHasher()

	password := "correctPassword"
	hash, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	err = hasher.VerifyPassword(password, hash)
	if err != nil {
		t.Errorf("expected password verification to succeed, got %v", err)
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	hasher := createTestHasher()

	password := "correctPassword"
	hash, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	err = hasher.VerifyPassword("wrongPassword", hash)
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestVerifyPassword_EmptyPassword(t *testing.T) {
	hasher := createTestHasher()

	// Hash empty password
	hash, err := hasher.HashPassword("")
	if err != nil {
		t.Fatalf("failed to hash empty password: %v", err)
	}

	// Verify with empty password
	err = hasher.VerifyPassword("", hash)
	if err != nil {
		t.Errorf("expected verification to succeed for empty password, got %v", err)
	}

	// Verify with non-empty password should fail
	err = hasher.VerifyPassword("notEmpty", hash)
	if err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestVerifyPassword_InvalidHashFormat(t *testing.T) {
	hasher := createTestHasher()

	invalidHashes := []string{
		"",
		"notahash",
		"$invalid$format",
		"$argon2id$v=19$m=65536",                // Too few parts
		"$wrong$v=19$m=65536,t=1,p=4$salt$hash", // Wrong algorithm
		"$argon2id$v=99$m=65536,t=1,p=4$salt$hash", // Wrong version
		"$argon2id$v=19$invalid$salt$hash",         // Invalid parameters
		"$argon2id$v=19$m=65536,t=1,p=4$!!!$hash",  // Invalid base64 salt
		"$argon2id$v=19$m=65536,t=1,p=4$salt$!!!",  // Invalid base64 hash
	}

	for _, hash := range invalidHashes {
		err := hasher.VerifyPassword("password", hash)
		if err == nil {
			t.Errorf("expected error for invalid hash: %s", hash)
		}
	}
}

// Round-trip Tests

func TestRoundTrip_MultiplePasswords(t *testing.T) {
	hasher := createTestHasher()

	passwords := []string{
		"simple",
		"Complex123!",
		"",
		"very long password with many words and characters 1234567890",
		"pāsswørd",
		"密码",
	}

	for _, password := range passwords {
		hash, err := hasher.HashPassword(password)
		if err != nil {
			t.Errorf("password %q: failed to hash: %v", password, err)
			continue
		}

		// Verify correct password
		err = hasher.VerifyPassword(password, hash)
		if err != nil {
			t.Errorf("password %q: verification failed: %v", password, err)
		}

		// Verify wrong password fails
		err = hasher.VerifyPassword(password+"wrong", hash)
		if err != auth.ErrInvalidCredentials {
			t.Errorf("password %q: expected verification to fail with wrong password", password)
		}
	}
}

func TestRoundTrip_CaseSensitivity(t *testing.T) {
	hasher := createTestHasher()

	password := "Password123"
	hash, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Correct case should work
	err = hasher.VerifyPassword("Password123", hash)
	if err != nil {
		t.Error("expected verification to succeed with correct case")
	}

	// Wrong case should fail
	err = hasher.VerifyPassword("password123", hash)
	if err != auth.ErrInvalidCredentials {
		t.Error("expected verification to fail with different case")
	}

	err = hasher.VerifyPassword("PASSWORD123", hash)
	if err != auth.ErrInvalidCredentials {
		t.Error("expected verification to fail with different case")
	}
}

func TestRoundTrip_WhitespaceMatters(t *testing.T) {
	hasher := createTestHasher()

	password := "password"
	hash, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Trailing space should fail
	err = hasher.VerifyPassword("password ", hash)
	if err != auth.ErrInvalidCredentials {
		t.Error("expected verification to fail with trailing space")
	}

	// Leading space should fail
	err = hasher.VerifyPassword(" password", hash)
	if err != auth.ErrInvalidCredentials {
		t.Error("expected verification to fail with leading space")
	}
}

// Configuration Tests

func TestHasher_DifferentConfigurations(t *testing.T) {
	configs := []*Config{
		{Memory: 16 * 1024, Iterations: 1, SaltLength: 16, KeyLength: 32, Parallelism: 2},
		{Memory: 64 * 1024, Iterations: 1, SaltLength: 16, KeyLength: 32, Parallelism: 4},
		{Memory: 256 * 1024, Iterations: 2, SaltLength: 32, KeyLength: 64, Parallelism: 8},
	}

	password := "testPassword"

	for i, config := range configs {
		hasher := NewHasher(config)

		hash, err := hasher.HashPassword(password)
		if err != nil {
			t.Errorf("config %d: failed to hash: %v", i, err)
			continue
		}

		// Hash should contain the configuration parameters
		if !strings.Contains(hash, "$m=") {
			t.Errorf("config %d: hash missing memory parameter", i)
		}

		// Verify works with same hasher
		err = hasher.VerifyPassword(password, hash)
		if err != nil {
			t.Errorf("config %d: verification failed: %v", i, err)
		}
	}
}

func TestHasher_CrossConfigurationVerification(t *testing.T) {
	// Hash with one configuration
	hasher1 := NewHasher(&Config{
		Memory:      64 * 1024,
		Iterations:  1,
		SaltLength:  16,
		KeyLength:   32,
		Parallelism: 4,
	})

	password := "testPassword"
	hash, err := hasher1.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Verify with different configuration hasher
	// Should still work because parameters are encoded in the hash
	hasher2 := NewHasher(&Config{
		Memory:      128 * 1024, // Different config
		Iterations:  2,
		SaltLength:  32,
		KeyLength:   64,
		Parallelism: 8,
	})

	err = hasher2.VerifyPassword(password, hash)
	if err != nil {
		t.Error("verification should work with different hasher config (params in hash)")
	}
}

// Security Tests

func TestHasher_ConstantTimeComparison(t *testing.T) {
	// This test can't directly verify constant-time behavior,
	// but we can ensure the comparison works correctly
	hasher := createTestHasher()

	password := "password"
	hash, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	// Verify that similar but wrong passwords still fail
	similarPasswords := []string{
		"passwor",   // One char short
		"password1", // One char extra
		"Password",  // Different case
		"passworD",  // Last char different
	}

	for _, similar := range similarPasswords {
		err := hasher.VerifyPassword(similar, hash)
		if err != auth.ErrInvalidCredentials {
			t.Errorf("expected verification to fail for similar password: %s", similar)
		}
	}
}
