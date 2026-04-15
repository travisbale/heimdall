package database

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// GetVerificationToken retrieves the email verification token for a user
func GetVerificationToken(t *testing.T, email string) string {
	t.Helper()

	var token string
	err := QueryRow(t,
		`SELECT vt.token FROM verification_tokens vt
		 JOIN users u ON u.id = vt.user_id
		 WHERE u.email = $1`, email).Scan(&token)
	require.NoError(t, err, "failed to get verification token for %s", email)

	return token
}

// GetPasswordResetToken retrieves the password reset token for a user
func GetPasswordResetToken(t *testing.T, email string) string {
	t.Helper()

	var token string
	err := QueryRow(t,
		`SELECT prt.token FROM password_reset_tokens prt
		 JOIN users u ON u.id = prt.user_id
		 WHERE u.email = $1`, email).Scan(&token)
	require.NoError(t, err, "failed to get password reset token for %s", email)

	return token
}
