package iam

import (
	"fmt"
	"strings"
)

// extractEmailDomain extracts the domain portion from an email address
// Returns an error if the email is invalid (missing @ symbol)
func extractEmailDomain(email string) (string, error) {
	// Find the @ symbol by searching backwards (more efficient for typical email formats)
	atIndex := strings.LastIndexByte(email, '@')
	if atIndex == -1 {
		return "", fmt.Errorf("invalid email format: missing @ symbol")
	}

	// Ensure there's content after the @
	if atIndex == len(email)-1 {
		return "", fmt.Errorf("invalid email format: missing domain")
	}

	return email[atIndex+1:], nil
}
