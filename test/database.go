//go:build integration

package test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// GetVerificationToken retrieves the verification token for a user by email
func GetVerificationToken(t *testing.T, db *pgxpool.Pool, email string) string {
	t.Helper()

	var token string
	err := db.QueryRow(context.Background(),
		`SELECT vt.token FROM verification_tokens vt
		 JOIN users u ON u.id = vt.user_id
		 WHERE u.email = $1`, email).Scan(&token)
	require.NoError(t, err, "failed to get verification token for %s", email)

	return token
}

// GetPasswordResetToken retrieves the password reset token for a user by email
func GetPasswordResetToken(t *testing.T, db *pgxpool.Pool, email string) string {
	t.Helper()

	var token string
	err := db.QueryRow(context.Background(),
		`SELECT prt.token FROM password_reset_tokens prt
		 JOIN users u ON u.id = prt.user_id
		 WHERE u.email = $1`, email).Scan(&token)
	require.NoError(t, err, "failed to get password reset token for %s", email)

	return token
}

// ClearLoginAttempts removes login attempt records for a user to reset lockout state
func ClearLoginAttempts(t *testing.T, db *pgxpool.Pool, email string) {
	t.Helper()

	_, err := db.Exec(context.Background(),
		`DELETE FROM login_attempts WHERE email = $1`, email)
	require.NoError(t, err, "failed to clear login attempts for %s", email)
}
