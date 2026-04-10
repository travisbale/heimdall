package email

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerificationURL(t *testing.T) {
	url := VerificationURL("https://app.example.com", "abc123")
	assert.Equal(t, "https://app.example.com/verify-email?token=abc123", url)
}

func TestPasswordResetURL(t *testing.T) {
	url := PasswordResetURL("https://app.example.com", "xyz789")
	assert.Equal(t, "https://app.example.com/reset-password?token=xyz789", url)
}
