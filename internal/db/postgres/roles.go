package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/internal/iam"
)

// RolesDB provides database operations for roles
type RolesDB struct {
	db *DB
}

// NewRolesDB creates a new RolesDB
func NewRolesDB(db *DB) *RolesDB {
	return &RolesDB{db: db}
}

// CreateRole creates a new role
func (r *RolesDB) CreateRole(ctx context.Context, role *iam.Role) (*iam.Role, error) {
	var createdRole *iam.Role
	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		tenantID, err := identity.GetTenant(ctx)
		if err != nil {
			return err
		}

		result, err := q.CreateRole(ctx, sqlc.CreateRoleParams{
			TenantID:    tenantID,
			Name:        role.Name,
			Description: role.Description,
			MfaRequired: role.MFARequired,
		})
		if err != nil {
			return err
		}

		createdRole = &iam.Role{
			ID:          result.ID,
			Name:        result.Name,
			Description: result.Description,
			MFARequired: result.MfaRequired,
		}
		return nil
	})

	return createdRole, err
}

// GetRoleByID retrieves a role by ID
func (r *RolesDB) GetRoleByID(ctx context.Context, roleID uuid.UUID) (*iam.Role, error) {
	var role *iam.Role
	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		result, err := q.GetRoleByID(ctx, roleID)
		if err != nil {
			return err
		}

		role = &iam.Role{
			ID:          result.ID,
			Name:        result.Name,
			Description: result.Description,
			MFARequired: result.MfaRequired,
		}
		return nil
	})

	return role, err
}

// ListRoles lists all roles for a tenant
func (r *RolesDB) ListRoles(ctx context.Context) ([]*iam.Role, error) {
	var roles []*iam.Role
	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		results, err := q.ListRoles(ctx)
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

// UpdateRole updates a role
func (r *RolesDB) UpdateRole(ctx context.Context, params iam.UpdateRoleParams) (*iam.Role, error) {
	var role *iam.Role
	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		result, err := q.UpdateRole(ctx, sqlc.UpdateRoleParams{
			ID:          params.ID,
			Name:        params.Name,
			Description: params.Description,
			MfaRequired: params.MFARequired,
		})
		if err != nil {
			return err
		}

		role = &iam.Role{
			ID:          result.ID,
			Name:        result.Name,
			Description: result.Description,
			MFARequired: result.MfaRequired,
		}
		return nil
	})

	return role, err
}

// DeleteRole deletes a role
func (r *RolesDB) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	return r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		return q.DeleteRole(ctx, roleID)
	})
}
