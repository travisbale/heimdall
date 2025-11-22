package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
)

// UserRolesDB provides database operations for user roles
type UserRolesDB struct {
	db *DB
}

// NewUserRolesDB creates a new UserRolesDB
func NewUserRolesDB(db *DB) *UserRolesDB {
	return &UserRolesDB{db: db}
}

// SetUserRoles sets all roles for a user (replaces existing roles)
// Roles are strictly tenant-scoped and tenant context is required
func (u *UserRolesDB) SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	return u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		// Delete all existing roles
		if err := q.SetUserRoles(ctx, userID); err != nil {
			return err
		}

		// Insert new roles (only if there are any)
		if len(roleIDs) > 0 {
			tenantID, err := identity.GetTenant(ctx)
			if err != nil {
				return err
			}

			return q.InsertUserRoles(ctx, sqlc.InsertUserRolesParams{
				UserID:   userID,
				RoleIds:  roleIDs,
				TenantID: tenantID,
			})
		}
		return nil
	})
}

// GetUserRoles retrieves all roles for a user
// Roles are strictly tenant-scoped and tenant context is required
func (u *UserRolesDB) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*auth.Role, error) {
	var roles []*auth.Role
	err := u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		results, err := q.GetUserRoles(ctx, userID)
		if err != nil {
			return err
		}

		roles = make([]*auth.Role, len(results))
		for i, result := range results {
			roles[i] = &auth.Role{
				ID:          result.ID,
				Name:        result.Name,
				Description: result.Description,
				MFARequired: result.MfaRequired,
			}
		}
		return nil
	})

	return roles, err
}
