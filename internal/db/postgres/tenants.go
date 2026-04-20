package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/knowhere/identity"
)

// TenantsDB provides database operations for tenants
type TenantsDB struct {
	db *DB
}

// NewTenantsDB creates a new TenantsDB
func NewTenantsDB(db *DB) *TenantsDB {
	return &TenantsDB{db: db}
}

// BootstrapTenant creates a new tenant with initial user and System Admin role
func (t *TenantsDB) BootstrapTenant(ctx context.Context, email, firstName, lastName string, status iam.UserStatus) (*iam.Tenant, *iam.User, error) {
	var tenant *iam.Tenant
	var user *iam.User

	tenantID := uuid.New()
	ctx = identity.WithTenant(ctx, tenantID)

	err := t.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		// Create tenant
		dbTenant, err := q.CreateTenant(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("failed to create tenant: %w", err)
		}

		tenant = &iam.Tenant{ID: dbTenant.ID}

		// Create user with empty password
		dbUser, err := q.CreateUser(ctx, sqlc.CreateUserParams{
			Email:        email,
			PasswordHash: "",
			FirstName:    firstName,
			LastName:     lastName,
			Status:       status,
		})
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		user, err = convertUserToDomain(dbUser)
		if err != nil {
			return err
		}

		// Create System Admin role
		role, err := q.CreateRole(ctx, sqlc.CreateRoleParams{
			Name:        "System Admin",
			Description: "Full system administrator with all permissions",
			MfaRequired: false,
		})
		if err != nil {
			return fmt.Errorf("failed to create System Admin role: %w", err)
		}

		// Assign all permissions to System Admin role
		permissions, err := q.ListPermissions(ctx)
		if err != nil {
			return fmt.Errorf("failed to list permissions: %w", err)
		}

		permissionIDs := make([]uuid.UUID, len(permissions))
		for i, perm := range permissions {
			permissionIDs[i] = perm.ID
		}

		if len(permissionIDs) > 0 {
			err = q.InsertRolePermissions(ctx, sqlc.InsertRolePermissionsParams{
				RoleID:        role.ID,
				PermissionIds: permissionIDs,
			})
			if err != nil {
				return fmt.Errorf("failed to assign permissions to System Admin role: %w", err)
			}
		}

		// Assign System Admin role to user
		err = q.InsertUserRoles(ctx, sqlc.InsertUserRolesParams{
			UserID:  user.ID,
			RoleIds: []uuid.UUID{role.ID},
		})
		if err != nil {
			return fmt.Errorf("failed to assign System Admin role to user: %w", err)
		}

		return nil
	})

	return tenant, user, err
}
