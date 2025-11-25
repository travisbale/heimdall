package iam

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/heimdall/sdk"
)

// RBACService handles role and permission management
// roleDB defines database operations for roles
type roleDB interface {
	CreateRole(ctx context.Context, role *Role) (*Role, error)
	GetRoleByID(ctx context.Context, roleID uuid.UUID) (*Role, error)
	ListRoles(ctx context.Context) ([]*Role, error)
	UpdateRole(ctx context.Context, params UpdateRoleParams) (*Role, error)
	DeleteRole(ctx context.Context, roleID uuid.UUID) error
}

// permissionDB defines database operations for permissions
type permissionDB interface {
	ListPermissions(ctx context.Context) ([]*Permission, error)
	GetPermissionByID(ctx context.Context, permissionID uuid.UUID) (*Permission, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*EffectivePermission, error)
}

// rolePermissionDB defines database operations for role permissions
type rolePermissionDB interface {
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*Permission, error)
	SetRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error
}

// userRoleDB defines database operations for user roles
type userRoleDB interface {
	SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*Role, error)
}

// userPermissionDB defines database operations for user permissions
type userPermissionDB interface {
	SetDirectPermissions(ctx context.Context, userID uuid.UUID, permissions []DirectPermission) error
	GetDirectPermissions(ctx context.Context, userID uuid.UUID) ([]*EffectivePermission, error)
}

// RBACServiceConfig holds the dependencies for creating an RBACService
type RBACServiceConfig struct {
	RolesDB           roleDB
	PermissionsDB     permissionDB
	RolePermissionsDB rolePermissionDB
	UserRolesDB       userRoleDB
	UserPermissionsDB userPermissionDB
	Logger            logger
}

type RBACService struct {
	rolesDB           roleDB
	permissionsDB     permissionDB
	rolePermissionsDB rolePermissionDB
	userRolesDB       userRoleDB
	userPermissionsDB userPermissionDB
	logger            logger
}

// NewRBACService creates a new RBACService
func NewRBACService(config *RBACServiceConfig) *RBACService {
	return &RBACService{
		rolesDB:           config.RolesDB,
		permissionsDB:     config.PermissionsDB,
		rolePermissionsDB: config.RolePermissionsDB,
		userRolesDB:       config.UserRolesDB,
		userPermissionsDB: config.UserPermissionsDB,
		logger:            config.Logger,
	}
}

// GetUserScopes returns all effective permission scopes for a user
func (s *RBACService) GetUserScopes(ctx context.Context, userID uuid.UUID) ([]sdk.Scope, error) {
	permissions, err := s.permissionsDB.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Build permission map: once denied, cannot be allowed
	permMap := make(map[sdk.Scope]bool)
	for _, perm := range permissions {
		scope := sdk.Scope(perm.Permission.Name)
		if perm.Effect == sdk.PermissionDeny {
			permMap[scope] = false
		} else {
			// Only set to allowed if not already denied
			if _, exists := permMap[scope]; !exists {
				permMap[scope] = true
			}
		}
	}

	result := make([]sdk.Scope, 0, len(permMap))
	for scope, allowed := range permMap {
		if allowed {
			result = append(result, scope)
		}
	}
	return result, nil
}

// CreateRole creates a new role
func (s *RBACService) CreateRole(ctx context.Context, role *Role) (*Role, error) {
	role, err := s.rolesDB.CreateRole(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}
	s.logger.Info(ctx, events.RoleCreated, "role_id", role.ID, "name", role.Name)
	return role, nil
}

// GetRole retrieves a role by ID
func (s *RBACService) GetRole(ctx context.Context, roleID uuid.UUID) (*Role, error) {
	return s.rolesDB.GetRoleByID(ctx, roleID)
}

// ListRoles lists all roles for the current tenant
func (s *RBACService) ListRoles(ctx context.Context) ([]*Role, error) {
	return s.rolesDB.ListRoles(ctx)
}

// UpdateRole updates a role
func (s *RBACService) UpdateRole(ctx context.Context, params UpdateRoleParams) (*Role, error) {
	role, err := s.rolesDB.UpdateRole(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}
	s.logger.Info(ctx, events.RoleUpdated, "role_id", params.ID)
	return role, nil
}

// DeleteRole deletes a role
func (s *RBACService) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	if err := s.rolesDB.DeleteRole(ctx, roleID); err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	s.logger.Info(ctx, events.RoleDeleted, "role_id", roleID)
	return nil
}

// GetRolePermissions retrieves all permissions for a role
func (s *RBACService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*Permission, error) {
	return s.rolePermissionsDB.GetRolePermissions(ctx, roleID)
}

// SetRolePermissions replaces all permissions for a role (bulk update)
func (s *RBACService) SetRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	if err := s.rolePermissionsDB.SetRolePermissions(ctx, roleID, permissionIDs); err != nil {
		return fmt.Errorf("failed to set role permissions: %w", err)
	}
	s.logger.Info(ctx, events.RolePermissionsUpdated, "role_id", roleID, "permission_count", len(permissionIDs))
	return nil
}

// SetUserRoles sets all roles for a user (replaces existing roles)
func (s *RBACService) SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	if err := s.userRolesDB.SetUserRoles(ctx, userID, roleIDs); err != nil {
		return fmt.Errorf("failed to set user roles: %w", err)
	}
	s.logger.Info(ctx, events.UserRolesUpdated, "user_id", userID, "role_count", len(roleIDs))
	return nil
}

// GetUserRoles retrieves all roles for a user
func (s *RBACService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*Role, error) {
	return s.userRolesDB.GetUserRoles(ctx, userID)
}

// SetDirectPermissions sets all direct permissions for a user (replaces existing direct permissions)
func (s *RBACService) SetDirectPermissions(ctx context.Context, userID uuid.UUID, permissions []DirectPermission) error {
	if err := s.userPermissionsDB.SetDirectPermissions(ctx, userID, permissions); err != nil {
		return fmt.Errorf("failed to set user permissions: %w", err)
	}
	s.logger.Info(ctx, events.UserPermissionsUpdated, "user_id", userID, "permission_count", len(permissions))
	return nil
}

// GetDirectPermissions retrieves direct permissions assigned to a user
func (s *RBACService) GetDirectPermissions(ctx context.Context, userID uuid.UUID) ([]*EffectivePermission, error) {
	return s.userPermissionsDB.GetDirectPermissions(ctx, userID)
}

// ListPermissions lists all available permissions (system-wide)
func (s *RBACService) ListPermissions(ctx context.Context) ([]*Permission, error) {
	return s.permissionsDB.ListPermissions(ctx)
}
