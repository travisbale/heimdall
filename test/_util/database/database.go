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
	_, err := getPool(t).Exec(context.Background(), query, args...)
	require.NoError(t, err, "failed to execute query: %s", query)
}

// QueryRow executes a query that returns a single row
func QueryRow(t *testing.T, query string, args ...any) pgx.Row {
	t.Helper()
	return getPool(t).QueryRow(context.Background(), query, args...)
}
