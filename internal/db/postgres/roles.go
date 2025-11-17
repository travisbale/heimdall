package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
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
func (r *RolesDB) CreateRole(ctx context.Context, name, description string) (*auth.Role, error) {
	var role *auth.Role
	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		tenantID, err := identity.GetTenant(ctx)
		if err != nil {
			return fmt.Errorf("failed to get tenant from context: %w", err)
		}

		result, err := q.CreateRole(ctx, sqlc.CreateRoleParams{
			TenantID:    tenantID,
			Name:        name,
			Description: description,
		})
		if err != nil {
			return err
		}

		role = &auth.Role{
			ID:          result.ID,
			TenantID:    result.TenantID,
			Name:        result.Name,
			Description: result.Description,
			CreatedAt:   result.CreatedAt,
			UpdatedAt:   result.UpdatedAt,
		}
		return nil
	})

	return role, err
}

// GetRoleByID retrieves a role by ID
func (r *RolesDB) GetRoleByID(ctx context.Context, roleID uuid.UUID) (*auth.Role, error) {
	var role *auth.Role
	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		result, err := q.GetRoleByID(ctx, roleID)
		if err != nil {
			return err
		}

		role = &auth.Role{
			ID:          result.ID,
			TenantID:    result.TenantID,
			Name:        result.Name,
			Description: result.Description,
			CreatedAt:   result.CreatedAt,
			UpdatedAt:   result.UpdatedAt,
		}
		return nil
	})

	return role, err
}

// GetRoleByName retrieves a role by name
func (r *RolesDB) GetRoleByName(ctx context.Context, name string) (*auth.Role, error) {
	var role *auth.Role
	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		tenantID, err := identity.GetTenant(ctx)
		if err != nil {
			return fmt.Errorf("failed to get tenant from context: %w", err)
		}

		result, err := q.GetRoleByName(ctx, sqlc.GetRoleByNameParams{
			TenantID: tenantID,
			Name:     name,
		})
		if err != nil {
			return err
		}

		role = &auth.Role{
			ID:          result.ID,
			TenantID:    result.TenantID,
			Name:        result.Name,
			Description: result.Description,
			CreatedAt:   result.CreatedAt,
			UpdatedAt:   result.UpdatedAt,
		}
		return nil
	})

	return role, err
}

// ListRoles lists all roles for a tenant
func (r *RolesDB) ListRoles(ctx context.Context) ([]*auth.Role, error) {
	var roles []*auth.Role
	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		results, err := q.ListRoles(ctx)
		if err != nil {
			return err
		}

		roles = make([]*auth.Role, len(results))
		for i, result := range results {
			roles[i] = &auth.Role{
				ID:          result.ID,
				TenantID:    result.TenantID,
				Name:        result.Name,
				Description: result.Description,
				CreatedAt:   result.CreatedAt,
				UpdatedAt:   result.UpdatedAt,
			}
		}
		return nil
	})

	return roles, err
}

// UpdateRole updates a role
func (r *RolesDB) UpdateRole(ctx context.Context, roleID uuid.UUID, name, description string) (*auth.Role, error) {
	var role *auth.Role
	err := r.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		result, err := q.UpdateRole(ctx, sqlc.UpdateRoleParams{
			ID:          roleID,
			Name:        name,
			Description: description,
		})
		if err != nil {
			return err
		}

		role = &auth.Role{
			ID:          result.ID,
			TenantID:    result.TenantID,
			Name:        result.Name,
			Description: result.Description,
			CreatedAt:   result.CreatedAt,
			UpdatedAt:   result.UpdatedAt,
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
