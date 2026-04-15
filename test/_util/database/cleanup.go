package database

import "testing"

// ClearLoginAttempts removes login attempt records to reset lockout state
func ClearLoginAttempts(t *testing.T, email string) {
	t.Helper()
	Exec(t, "DELETE FROM login_attempts WHERE email = $1", email)
}
