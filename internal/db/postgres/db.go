package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/tenant"
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
// Use this for operations that don't require tenant scoping
func (d *DB) WithTransaction(ctx context.Context, fn func(*sqlc.Queries) error) error {
	// Begin transaction
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	// Rollback is safe to call even if the transaction is later committed
	defer func() {
		if err2 := tx.Rollback(ctx); err2 != nil {
			slog.Error("failed to rollback transaction", "error", err2)
		}
	}()

	// Execute function
	queries := sqlc.New(tx)
	if err := fn(queries); err != nil {
		return err
	}

	// Commit transaction
	return tx.Commit(ctx)
}

// WithTenantContext executes a function within a tenant-scoped transaction.
// This sets the app.current_tenant_id session variable which is used by
// Row Level Security (RLS) policies to automatically filter queries.
func (d *DB) WithTenantContext(ctx context.Context, fn func(*sqlc.Queries) error) error {
	// Extract tenant ID from context
	tenantID, err := tenant.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tenant from context: %w", err)
	}

	// Begin transaction
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	// Rollback is safe to call even if the transaction is later committed
	defer func() {
		if err2 := tx.Rollback(ctx); err2 != nil {
			slog.Error("failed to rollback transaction", "error", err2)
		}
	}()

	// Set tenant context for RLS
	_, err = tx.Exec(ctx, "SET LOCAL app.current_tenant_id = $1", tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to set tenant context: %w", err)
	}

	// Execute function with tenant-scoped queries
	queries := sqlc.New(tx)
	if err := fn(queries); err != nil {
		return err
	}

	// Commit transaction
	return tx.Commit(ctx)
}
