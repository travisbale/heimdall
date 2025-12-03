package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/knowhere/db/postgres"
)

// DB is the database connection for heimdall
type DB = postgres.DB[*sqlc.Queries]

// NewDB creates a new database connection pool
func NewDB(ctx context.Context, databaseURL string) (*DB, error) {
	cfg := postgres.DefaultConfig()

	// Load custom types (enums) from database for each connection
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.LoadTypes(ctx, []string{"permission_effect", "_permission_effect"})
		return err
	}

	// Wrap sqlc.New to satisfy the db.NewDB constructor signature
	queries := func(d any) *sqlc.Queries {
		return sqlc.New(d.(sqlc.DBTX))
	}

	return postgres.NewDB(ctx, databaseURL, queries, cfg)
}
