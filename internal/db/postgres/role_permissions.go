package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/internal/iam"
)

// RolePermissionsDB provides database operations for role permissions
type RolePermissionsDB struct {
	db *DB
}

// NewRolePermissionsDB creates a new RolePermissionsDB
func NewRolePermissionsDB(db *DB) *RolePermissionsDB {
	return &RolePermissionsDB{db: db}
}

// GetRolePermissions retrieves all permissions for a role
func (r *RolePermissionsDB) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*iam.Permission, error) {
	var permissions []*iam.Permission
	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		results, err := q.GetRolePermissions(ctx, roleID)
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

// SetRolePermissions replaces all permissions for a role (bulk update)
func (r *RolePermissionsDB) SetRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		if err := q.DeleteAllRolePermissions(ctx, roleID); err != nil {
			return err
		}

		if len(permissionIDs) > 0 {
			return q.InsertRolePermissions(ctx, sqlc.InsertRolePermissionsParams{
				Column1: roleID,
				Column2: permissionIDs,
			})
		}

		return nil
	})
}
