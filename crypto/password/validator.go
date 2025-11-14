package password

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// MinLength is the minimum password length following NIST guidelines
	MinLength = 10
	// MaxLength prevents DoS attacks on Argon2 hashing
	MaxLength = 128
	// HIBPAPITimeout is the timeout for Have I Been Pwned API calls
	HIBPAPITimeout = 3 * time.Second
	// HIBPURL is the Have I Been Pwned API endpoint
	HIBPURL = "https://api.pwnedpasswords.com/range/"
)

// ValidationError represents a password validation failure
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// Validator validates passwords against security policies
type Validator struct {
	httpClient      *http.Client
	commonPasswords map[string]bool
}

// NewValidator creates a new password validator
func NewValidator() *Validator {
	return &Validator{
		httpClient: &http.Client{
			Timeout: HIBPAPITimeout,
		},
		commonPasswords: buildCommonPasswordsMap(),
	}
}

// Validate checks if a password meets security requirements
func (v *Validator) Validate(ctx context.Context, password string) error {
	length := utf8.RuneCountInString(password)
	if length < MinLength {
		return &ValidationError{
			Message: fmt.Sprintf("password must be at least %d characters", MinLength),
		}
	}

	if length > MaxLength {
		return &ValidationError{
			Message: fmt.Sprintf("password must not exceed %d characters", MaxLength),
		}
	}

	if v.isCommonPassword(password) {
		return &ValidationError{
			Message: "password is too common and easily guessed",
		}
	}

	if breached, err := v.isBreached(ctx, password); err != nil {
		// Log error but don't fail validation if API is unreachable
		// Security decision: availability > perfect security for this check
		return nil
	} else if breached {
		return &ValidationError{
			Message: "password has been found in data breaches and is not secure",
		}
	}

	return nil
}

// isCommonPassword checks if password is in the common passwords list
func (v *Validator) isCommonPassword(password string) bool {
	// Case-insensitive check since users often capitalize first letter
	return v.commonPasswords[strings.ToLower(password)]
}

// isBreached checks if password appears in Have I Been Pwned database
// Uses k-anonymity model: only sends first 5 chars of SHA-1 hash to API
func (v *Validator) isBreached(ctx context.Context, password string) (bool, error) {
	// Generate SHA-1 hash of password
	hash := sha1.New()
	hash.Write([]byte(password))
	hashBytes := hash.Sum(nil)
	hashStr := strings.ToUpper(hex.EncodeToString(hashBytes))

	// k-anonymity: send only first 5 characters of hash
	prefix := hashStr[:5]
	suffix := hashStr[5:]

	// Query Have I Been Pwned API
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, HIBPURL+prefix, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create HIBP request: %w", err)
	}

	// Add user agent as required by HIBP API
	req.Header.Set("User-Agent", "Heimdall-Auth-Service")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to query HIBP API: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HIBP API returned status %d", resp.StatusCode)
	}

	// Read response body (list of hash suffixes with occurrence counts)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read HIBP response: %w", err)
	}

	// Parse response: each line is "HASHSUFFIX:COUNT"
	for line := range strings.SplitSeq(string(body), "\n") {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) != 2 {
			continue
		}

		// Check if our hash suffix matches
		if parts[0] == suffix {
			// Parse occurrence count
			count, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
			// If count > 0, password has been breached
			return count > 0, nil
		}
	}

	// Hash suffix not found in response = password not breached
	return false, nil
}
