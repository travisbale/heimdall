package postgres

import (
	"embed"

	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/travisbale/knowhere/db"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrateUp applies all pending migrations
func MigrateUp(databaseURL string) error {
	return db.MigrateUp(migrationsFS, "migrations", databaseURL)
}

// MigrateDown rolls back the last migration
func MigrateDown(databaseURL string) error {
	return db.MigrateDown(migrationsFS, "migrations", databaseURL)
}

// MigrateVersion returns the current migration version
func MigrateVersion(databaseURL string) (uint, bool, error) {
	return db.MigrateVersion(migrationsFS, "migrations", databaseURL)
}
