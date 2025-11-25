package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/internal/iam"
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
func (p *PermissionsDB) ListPermissions(ctx context.Context) ([]*iam.Permission, error) {
	var permissions []*iam.Permission
	err := p.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		results, err := q.ListPermissions(ctx)
		if err != nil {
			return err
		}

		permissions = make([]*iam.Permission, len(results))
		for i, result := range results {
			permissions[i] = &iam.Permission{
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
func (p *PermissionsDB) GetPermissionByID(ctx context.Context, permissionID uuid.UUID) (*iam.Permission, error) {
	var permission *iam.Permission
	err := p.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		result, err := q.GetPermissionByID(ctx, permissionID)
		if err != nil {
			return err
		}

		permission = &iam.Permission{
			ID:          result.ID,
			Name:        result.Name,
			Description: result.Description,
		}
		return nil
	})

	return permission, err
}

// GetUserPermissions retrieves all permissions for a user (from roles + direct)
func (p *PermissionsDB) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*iam.EffectivePermission, error) {
	var permissions []*iam.EffectivePermission
	err := p.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		results, err := q.GetUserPermissions(ctx, userID)
		if err != nil {
			return err
		}

		permissions = make([]*iam.EffectivePermission, len(results))
		for i, result := range results {
			permissions[i] = &iam.EffectivePermission{
				Permission: &iam.Permission{
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
