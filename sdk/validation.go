package sdk

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"unicode/utf8"
)

// emailRegex is a basic email validation pattern
// Matches standard email format: localpart@domain
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// validateEmail checks if the email has a valid format
func validateEmail(email string) error {
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// Password length is part of the request contract, so a client can reject a bad one
// without a round trip. The minimum follows NIST guidance; the maximum bounds the work
// Argon2 is asked to do on an unauthenticated request.
//
// Whether a password is *guessable* is not here. That needs a word list and a lookup
// against a breach corpus, it can change for a password that has not, and it is the
// server's call — see internal/password.
const (
	MinPasswordLength = 10
	MaxPasswordLength = 128
)

// validatePasswordLength checks the one password property a client can check for itself.
func validatePasswordLength(password string) error {
	length := utf8.RuneCountInString(password)
	if length < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if length > MaxPasswordLength {
		return fmt.Errorf("password must not exceed %d characters", MaxPasswordLength)
	}
	return nil
}

// validateRequired checks if a string field is non-empty after trimming whitespace
func validateRequired(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", fieldName)
	}
	return nil
}

// validateUUID checks if a UUID field is not nil
func validateUUID(id uuid.UUID, fieldName string) error {
	if id == uuid.Nil {
		return fmt.Errorf("%s is required", fieldName)
	}
	return nil
}

// validateNotEmpty checks if an optional string pointer is not empty when provided
func validateNotEmpty(value *string, fieldName string) error {
	if value != nil && strings.TrimSpace(*value) == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	return nil
}
