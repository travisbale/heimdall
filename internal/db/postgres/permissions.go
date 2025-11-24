package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
)

// PermissionsDB provides database operations for permissions
type PermissionsDB struct {
	db *DB
}

// NewPermissionsDB creates a new PermissionsDB
func NewPermissionsDB(db *DB) *PermissionsDB {
	return &PermissionsDB{db: db}
}

// ListPermissions lists all available permissions (system-wide)
func (p *PermissionsDB) ListPermissions(ctx context.Context) ([]*auth.Permission, error) {
	var permissions []*auth.Permission
	err := p.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		results, err := q.ListPermissions(ctx)
		if err != nil {
			return err
		}

		permissions = make([]*auth.Permission, len(results))
		for i, result := range results {
			permissions[i] = &auth.Permission{
				ID:          result.ID,
				Name:        result.Name,
				Description: result.Description,
			}
		}
		return nil
	})

	return permissions, err
}

// GetPermissionByID retrieves a permission by ID
func (p *PermissionsDB) GetPermissionByID(ctx context.Context, permissionID uuid.UUID) (*auth.Permission, error) {
	var permission *auth.Permission
	err := p.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		result, err := q.GetPermissionByID(ctx, permissionID)
		if err != nil {
			return err
		}

		permission = &auth.Permission{
			ID:          result.ID,
			Name:        result.Name,
			Description: result.Description,
		}
		return nil
	})

	return permission, err
}

// GetUserPermissions retrieves all permissions for a user (from roles + direct)
func (p *PermissionsDB) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*auth.EffectivePermission, error) {
	ctx, err := p.db.SetTenantContext(ctx, userID)
	if err != nil {
		return nil, err
	}

	var permissions []*auth.EffectivePermission
	err = p.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		results, err := q.GetUserPermissions(ctx, userID)
		if err != nil {
			return err
		}

		permissions = make([]*auth.EffectivePermission, len(results))
		for i, result := range results {
			permissions[i] = &auth.EffectivePermission{
				Permission: &auth.Permission{
					ID:          result.ID,
					Name:        result.Name,
					Description: result.Description,
				},
				Effect: result.Effect,
			}
		}
		return nil
	})

	return permissions, err
}
