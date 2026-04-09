package iam

import (
	"context"
	"fmt"
	"log/slog"

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

type RBACService struct {
	RolesDB           roleDB
	PermissionsDB     permissionDB
	RolePermissionsDB rolePermissionDB
	UserRolesDB       userRoleDB
	UserPermissionsDB userPermissionDB
	Logger            *slog.Logger
}

// GetUserScopes returns all effective permission scopes for a user
func (s *RBACService) GetUserScopes(ctx context.Context, userID uuid.UUID) ([]Scope, error) {
	permissions, err := s.PermissionsDB.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Build permission map: once denied, cannot be allowed
	permMap := make(map[Scope]bool)
	for _, perm := range permissions {
		scope := Scope(perm.Permission.Name)
		if perm.Effect == sdk.PermissionDeny {
			permMap[scope] = false
		} else {
			// Only set to allowed if not already denied
			if _, exists := permMap[scope]; !exists {
				permMap[scope] = true
			}
		}
	}

	result := make([]Scope, 0, len(permMap))
	for scope, allowed := range permMap {
		if allowed {
			result = append(result, scope)
		}
	}
	return result, nil
}

// CreateRole creates a new role
func (s *RBACService) CreateRole(ctx context.Context, role *Role) (*Role, error) {
	role, err := s.RolesDB.CreateRole(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}
	s.Logger.InfoContext(ctx, events.RoleCreated, "role_id", role.ID, "name", role.Name)
	return role, nil
}

// GetRole retrieves a role by ID
func (s *RBACService) GetRole(ctx context.Context, roleID uuid.UUID) (*Role, error) {
	return s.RolesDB.GetRoleByID(ctx, roleID)
}

// ListRoles lists all roles for the current tenant
func (s *RBACService) ListRoles(ctx context.Context) ([]*Role, error) {
	return s.RolesDB.ListRoles(ctx)
}

// UpdateRole updates a role
func (s *RBACService) UpdateRole(ctx context.Context, params UpdateRoleParams) (*Role, error) {
	role, err := s.RolesDB.UpdateRole(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}
	s.Logger.InfoContext(ctx, events.RoleUpdated, "role_id", params.ID)
	return role, nil
}

// DeleteRole deletes a role
func (s *RBACService) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	if err := s.RolesDB.DeleteRole(ctx, roleID); err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	s.Logger.InfoContext(ctx, events.RoleDeleted, "role_id", roleID)
	return nil
}

// GetRolePermissions retrieves all permissions for a role
func (s *RBACService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*Permission, error) {
	return s.RolePermissionsDB.GetRolePermissions(ctx, roleID)
}

// SetRolePermissions replaces all permissions for a role (bulk update)
func (s *RBACService) SetRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	if err := s.RolePermissionsDB.SetRolePermissions(ctx, roleID, permissionIDs); err != nil {
		return fmt.Errorf("failed to set role permissions: %w", err)
	}
	s.Logger.InfoContext(ctx, events.RolePermissionsUpdated, "role_id", roleID, "permission_count", len(permissionIDs))
	return nil
}

// SetUserRoles sets all roles for a user (replaces existing roles)
func (s *RBACService) SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	if err := s.UserRolesDB.SetUserRoles(ctx, userID, roleIDs); err != nil {
		return fmt.Errorf("failed to set user roles: %w", err)
	}
	s.Logger.InfoContext(ctx, events.UserRolesUpdated, "user_id", userID, "role_count", len(roleIDs))
	return nil
}

// GetUserRoles retrieves all roles for a user
func (s *RBACService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*Role, error) {
	return s.UserRolesDB.GetUserRoles(ctx, userID)
}

// SetDirectPermissions sets all direct permissions for a user (replaces existing direct permissions)
func (s *RBACService) SetDirectPermissions(ctx context.Context, userID uuid.UUID, permissions []DirectPermission) error {
	if err := s.UserPermissionsDB.SetDirectPermissions(ctx, userID, permissions); err != nil {
		return fmt.Errorf("failed to set user permissions: %w", err)
	}
	s.Logger.InfoContext(ctx, events.UserPermissionsUpdated, "user_id", userID, "permission_count", len(permissions))
	return nil
}

// GetDirectPermissions retrieves direct permissions assigned to a user
func (s *RBACService) GetDirectPermissions(ctx context.Context, userID uuid.UUID) ([]*EffectivePermission, error) {
	return s.UserPermissionsDB.GetDirectPermissions(ctx, userID)
}

// ListPermissions lists all available permissions (system-wide)
func (s *RBACService) ListPermissions(ctx context.Context) ([]*Permission, error) {
	return s.PermissionsDB.ListPermissions(ctx)
}

// UserRolesRequireMFA checks if any of the user's assigned roles require MFA
func (s *RBACService) UserRolesRequireMFA(ctx context.Context, userID uuid.UUID) (bool, error) {
	roles, err := s.UserRolesDB.GetUserRoles(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user roles: %w", err)
	}
	for _, role := range roles {
		if role.MFARequired {
			return true, nil
		}
	}
	return false, nil
}
