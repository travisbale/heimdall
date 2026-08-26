package iam

import (
	"fmt"
	"strings"
)

// extractEmailDomain returns what follows the address's final @, which is the delimiter —
// an earlier one can be part of a quoted local part.
func extractEmailDomain(email string) (string, error) {
	atIndex := strings.LastIndexByte(email, '@')
	if atIndex == -1 {
		return "", fmt.Errorf("invalid email format: missing @ symbol")
	}

	if atIndex == len(email)-1 {
		return "", fmt.Errorf("invalid email format: missing domain")
	}

	return email[atIndex+1:], nil
}
