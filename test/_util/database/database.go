package database

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Superuser connection for test queries — bypasses RLS for token extraction and cleanup
const databaseURL = "postgres://superuser:superuser@localhost:5432/heimdall?sslmode=disable"

var (
	pool   *pgxpool.Pool
	poolMu sync.Mutex
)

func getPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	poolMu.Lock()
	defer poolMu.Unlock()

	if pool != nil {
		return pool
	}

	var err error
	pool, err = pgxpool.New(context.Background(), databaseURL)
	require.NoError(t, err, "failed to connect to test database")

	return pool
}

// Exec executes a SQL statement and fails the test on error
func Exec(t *testing.T, query string, args ...any) {
	t.Helper()
	ExecRows(t, query, args...)
}

// QueryRow executes a query that returns a single row
func QueryRow(t *testing.T, query string, args ...any) pgx.Row {
	t.Helper()
	return getPool(t).QueryRow(context.Background(), query, args...)
}

// ExecRows is Exec, returning the number of rows it touched. A fixture that updates nothing
// still succeeds, so a test that has to change a specific row asserts on this rather than
// trusting the statement ran.
func ExecRows(t *testing.T, query string, args ...any) int64 {
	t.Helper()
	tag, err := getPool(t).Exec(context.Background(), query, args...)
	require.NoError(t, err, "failed to execute query: %s", query)
	return tag.RowsAffected()
}

// SetUserStatus moves an account's status, and asserts it moved a row: a WHERE that matches
// nothing succeeds, and a test whose subject was never deactivated goes green having proved
// the opposite of what it says.
func SetUserStatus(t *testing.T, email, status string) {
	t.Helper()
	rows := ExecRows(t, "UPDATE users SET status = $1 WHERE email = $2", status, email)
	require.EqualValues(t, 1, rows, "the account under test must be the one whose status moved")
}
