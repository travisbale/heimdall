package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
)

type logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// DB wraps the pgx connection pool
type DB struct {
	pool   *pgxpool.Pool
	logger logger
}

// NewDB creates a new database connection pool
func NewDB(ctx context.Context, databaseURL string, logger logger) (*DB, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Configure connection pool
	config.MaxConns = 25
	config.MinConns = 5
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 30 * time.Minute
	config.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{
		pool:   pool,
		logger: logger,
	}, nil
}

// Close closes the database connection pool
func (d *DB) Close() {
	d.pool.Close()
}

// Health checks if the database is healthy
func (d *DB) Health(ctx context.Context) error {
	return d.pool.Ping(ctx)
}

// Queries returns a new Queries instance for executing SQL queries
func (d *DB) Queries() *sqlc.Queries {
	return sqlc.New(d.pool)
}

// Pool returns the underlying pgx connection pool
func (d *DB) Pool() *pgxpool.Pool {
	return d.pool
}

// WithTransaction executes a function within a database transaction.
// Use for pre-authentication operations (registration, email verification) where tenant context is unavailable
func (d *DB) WithTransaction(ctx context.Context, fn func(*sqlc.Queries) error) error {
	// Empty string signals cross-tenant operation for RLS policies
	return d.withTenantTransaction(ctx, "", fn)
}

// WithTenantContext executes a function within a tenant-scoped transaction.
// Sets app.current_tenant_id for Row Level Security policies to enforce automatic tenant isolation
func (d *DB) WithTenantContext(ctx context.Context, fn func(*sqlc.Queries) error) error {
	tenantID, err := identity.GetTenant(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tenant from context: %w", err)
	}

	return d.withTenantTransaction(ctx, tenantID.String(), fn)
}

// withTenantTransaction executes a function within a transaction with the specified tenant ID.
// tenantID should be a UUID string or empty string for cross-tenant operations
func (d *DB) withTenantTransaction(ctx context.Context, tenantID string, fn func(*sqlc.Queries) error) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	// Deferred rollback is safe even if transaction commits successfully
	defer func() {
		if err2 := tx.Rollback(ctx); err2 != nil {
			slog.Error("failed to rollback transaction", "error", err2)
		}
	}()

	// SET LOCAL ensures the tenant context lasts only for this transaction
	query := fmt.Sprintf("SET LOCAL app.current_tenant_id = '%s'", tenantID)
	_, err = tx.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to set tenant context: %w", err)
	}

	queries := sqlc.New(tx)
	if err := fn(queries); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
