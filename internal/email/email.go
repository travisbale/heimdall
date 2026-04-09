// Package email defines shared constants and helpers for email providers.
package email

import "fmt"

// Template identifiers for email types
const (
	VerificationTemplate  = "email-verification"
	PasswordResetTemplate = "password-reset"
)

// VerificationURL constructs the email verification URL for a given token
func VerificationURL(publicURL, token string) string {
	return fmt.Sprintf("%s/verify-email?token=%s", publicURL, token)
}

// PasswordResetURL constructs the password reset URL for a given token
func PasswordResetURL(publicURL, token string) string {
	return fmt.Sprintf("%s/reset-password?token=%s", publicURL, token)
}
