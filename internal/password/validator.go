package password

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// MinLength follows NIST guidance; MaxLength bounds the work Argon2 is asked to do on
	// an unauthenticated request.
	MinLength = 10
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

// Validator rejects passwords that are known to be guessable — present in a list of
// common choices, or seen in a public breach corpus. This is policy rather than shape:
// it needs a word list and a network call, and the answer changes over time for a
// password that never did. Length limits live in the request contract instead, where a
// client can check them without either.
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

// Validate reports whether a password is acceptable: long enough, not a common choice,
// and not in a public breach corpus. All of it happens here so a password is checked once,
// in one place, rather than having its length judged at the boundary and the rest later.
//
// A password is accepted when the breach lookup fails. That trades a weaker check for
// availability — a password reset should not become impossible because a third-party API
// is down — but it is a real gap, so it is logged rather than passed over in silence.
func (v *Validator) Validate(ctx context.Context, password string) error {
	// Counted in runes, not bytes: a ten character Cyrillic password is ten characters,
	// and counting bytes would reject it while letting a shorter one through.
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

	breached, err := v.isBreached(ctx, password)
	if err != nil {
		slog.WarnContext(ctx, "breach check unavailable, accepting password unchecked", "error", err)
		return nil
	}
	if breached {
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
