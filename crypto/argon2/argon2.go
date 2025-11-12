package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/travisbale/heimdall/internal/auth"
	"golang.org/x/crypto/argon2"
)

// HashPassword generates an Argon2id hash of the password
// Returns the hash in the format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
func hashPassword(memory, iterations, saltLength, keyLength uint32, parallelism uint8, password string) (string, error) {
	// Generate a cryptographically secure random salt
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate the hash using Argon2id
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)

	// Encode salt and hash to base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, iterations, parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

// CompareHashAndPassword verifies that the provided password matches the hash
func compareHashAndPassword(password, encodedHash string) error {
	// Parse the encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return fmt.Errorf("invalid hash format")
	}

	// Validate algorithm
	if parts[1] != "argon2id" {
		return fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	// Parse version
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return fmt.Errorf("failed to parse version: %w", err)
	}
	if version != argon2.Version {
		return fmt.Errorf("unsupported version: %d", version)
	}

	// Parse parameters
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return fmt.Errorf("failed to parse parameters: %w", err)
	}

	// Decode salt
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	// Decode hash
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("failed to decode hash: %w", err)
	}

	// Generate hash from provided password using extracted parameters
	comparisonHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(hash)))

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(hash, comparisonHash) == 1 {
		return nil
	}

	return auth.ErrInvalidCredentials
}
