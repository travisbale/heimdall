package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/knowhere/identity"
)

// sweepTenants runs a maintenance delete once per tenant, each inside that tenant's context.
//
// The tables the cleanup empties are under FORCE ROW LEVEL SECURITY with policies keyed on
// current_tenant_id(). Run without a tenant the predicate is NULL for every row, so the
// delete matches nothing and reports no error — a cleanup that prints success and leaves the
// table exactly as it found it. Covered by test/postgres/cleanup_test.go.
func sweepTenants(ctx context.Context, db *DB, del func(context.Context, *sqlc.Queries) error) error {
	var tenantIDs []uuid.UUID
	if err := db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		var err error
		tenantIDs, err = q.ListTenantIDs(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	for _, tenantID := range tenantIDs {
		tenantCtx := identity.WithTenant(ctx, tenantID)
		if err := db.WithTenantContext(tenantCtx, func(q *sqlc.Queries) error {
			return del(tenantCtx, q)
		}); err != nil {
			return fmt.Errorf("tenant %s: %w", tenantID, err)
		}
	}
	return nil
}
