package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/internal/iam"
)

// UserPermissionsDB provides database operations for direct user permissions
type UserPermissionsDB struct {
	db *DB
}

// NewUserPermissionsDB creates a new UserPermissionsDB
func NewUserPermissionsDB(db *DB) *UserPermissionsDB {
	return &UserPermissionsDB{db: db}
}

// SetDirectPermissions sets all direct permissions for a user (replaces existing direct permissions)
func (u *UserPermissionsDB) SetDirectPermissions(ctx context.Context, userID uuid.UUID, permissions []iam.DirectPermission) error {
	return u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		if err := q.DeleteAllDirectPermissions(ctx, userID); err != nil {
			return err
		}

		// Insert new permissions (only if there are any)
		if len(permissions) > 0 {
			permissionIDs := make([]uuid.UUID, len(permissions))
			effects := make([]string, len(permissions))
			for i, perm := range permissions {
				permissionIDs[i] = perm.PermissionID
				effects[i] = string(perm.Effect) // Convert enum to string for PostgreSQL
			}

			return q.InsertDirectPermissions(ctx, sqlc.InsertDirectPermissionsParams{
				UserID:        userID,
				PermissionIds: permissionIDs,
				Effects:       effects,
			})
		}
		return nil
	})
}

// GetDirectPermissions retrieves direct permissions assigned to a user
func (u *UserPermissionsDB) GetDirectPermissions(ctx context.Context, userID uuid.UUID) ([]*iam.EffectivePermission, error) {
	var assignments []*iam.EffectivePermission
	err := u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		results, err := q.GetDirectPermissions(ctx, userID)
		if err != nil {
			return err
		}

		assignments = make([]*iam.EffectivePermission, len(results))
		for i, result := range results {
			assignments[i] = &iam.EffectivePermission{
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

	return assignments, err
}
