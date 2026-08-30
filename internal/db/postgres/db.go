package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/knowhere/db/postgres"
)

type DB = postgres.DB[*sqlc.Queries]

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

// uniqueViolation reports whether err is Postgres refusing a duplicate, and hands back the
// driver error so a caller with more than one unique index can tell which one refused.
func uniqueViolation(err error) (*pgconn.PgError, bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return pgErr, true
	}
	return nil, false
}
