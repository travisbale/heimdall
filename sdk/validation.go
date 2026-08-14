package sdk

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
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
