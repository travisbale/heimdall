package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
)

// TenantsDB provides database operations for tenants
type TenantsDB struct {
	db *DB
}

// NewTenantsDB creates a new TenantsDB
func NewTenantsDB(db *DB) *TenantsDB {
	return &TenantsDB{db: db}
}

// CreateTenant creates a new tenant in the database
func (t *TenantsDB) CreateTenant(ctx context.Context, tenantID uuid.UUID) (*auth.Tenant, error) {
	var result *auth.Tenant

	err := t.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbTenant, err := q.CreateTenant(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("failed to create tenant: %w", err)
		}

		result = &auth.Tenant{
			ID:        dbTenant.ID,
			CreatedAt: dbTenant.CreatedAt,
			UpdatedAt: dbTenant.UpdatedAt,
		}
		return nil
	})

	return result, err
}
