package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/internal/iam"
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
func (u *UserRolesDB) SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	return u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		if err := q.DeleteAllUserRoles(ctx, userID); err != nil {
			return err
		}

		if len(roleIDs) > 0 {
			return q.InsertUserRoles(ctx, sqlc.InsertUserRolesParams{
				UserID:  userID,
				RoleIds: roleIDs,
			})
		}
		return nil
	})
}

// GetUserRoles retrieves all roles for a user
func (u *UserRolesDB) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*iam.Role, error) {
	// If tenant context exists (API call with JWT), use caller's tenant for isolation.
	if _, err := identity.GetTenant(ctx); err != nil {
		// If not (auth flow), look up tenant from userID.
		ctx, err = u.db.SetTenantContext(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to set tenant context: %w", err)
		}
	}

	var roles []*iam.Role
	err := u.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		results, err := q.GetUserRoles(ctx, userID)
		if err != nil {
			return err
		}

		roles = make([]*iam.Role, len(results))
		for i, result := range results {
			roles[i] = &iam.Role{
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
