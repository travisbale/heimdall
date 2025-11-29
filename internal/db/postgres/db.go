package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	db "github.com/travisbale/knowhere/db/postgres"
)

// DB is the database connection for heimdall
type DB = db.DB[*sqlc.Queries]

// queries wraps sqlc.New to satisfy the db.NewDB constructor signature
func queries(d any) *sqlc.Queries {
	return sqlc.New(d.(sqlc.DBTX))
}

// NewDB creates a new database connection pool
func NewDB(ctx context.Context, databaseURL string) (*DB, error) {
	cfg := db.DefaultConfig()

	// Load custom types (enums) from database for each connection
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.LoadTypes(ctx, []string{"permission_effect", "_permission_effect"})
		return err
	}

	return db.NewDB(ctx, databaseURL, queries, cfg)
}
