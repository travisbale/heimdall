package sdk

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// PermissionEffect represents the effect of a permission (allow/deny)
type PermissionEffect string

const (
	PermissionAllow PermissionEffect = "allow"
	PermissionDeny  PermissionEffect = "deny"
)

// Permission represents a system permission
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

// PermissionsResponse represents the response with a list of permissions
type PermissionsResponse struct {
	Permissions []Permission `json:"permissions"`
}

// Role represents a role with its metadata
type Role struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	MFARequired bool      `json:"mfa_required"`
}

// CreateRoleRequest represents the request to create a new role
type CreateRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	MFARequired bool   `json:"mfa_required"`
}

// Validate validates the create role request
func (r *CreateRoleRequest) Validate(ctx context.Context) error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(r.Description) == "" {
		return fmt.Errorf("description is required")
	}
	return nil
}

// UpdateRoleRequest represents the request to update a role (supports partial updates)
type UpdateRoleRequest struct {
	RoleID      uuid.UUID `json:"-"`
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	MFARequired *bool     `json:"mfa_required,omitempty"`
}

// Validate validates the update role request
func (r *UpdateRoleRequest) Validate(ctx context.Context) error {
	if r.RoleID == uuid.Nil {
		return fmt.Errorf("role_id is required")
	}
	if r.Name != nil && strings.TrimSpace(*r.Name) == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if r.Description != nil && strings.TrimSpace(*r.Description) == "" {
		return fmt.Errorf("description cannot be empty")
	}
	return nil
}

// GetRoleRequest represents the request to get a role
type GetRoleRequest struct {
	RoleID uuid.UUID `json:"-"`
}

// Validate validates the get role request
func (r *GetRoleRequest) Validate(ctx context.Context) error {
	if r.RoleID == uuid.Nil {
		return fmt.Errorf("role_id is required")
	}
	return nil
}

// DeleteRoleRequest represents the request to delete a role
type DeleteRoleRequest struct {
	RoleID uuid.UUID `json:"-"`
}

// Validate validates the delete role request
func (r *DeleteRoleRequest) Validate(ctx context.Context) error {
	if r.RoleID == uuid.Nil {
		return fmt.Errorf("role_id is required")
	}
	return nil
}

// RolesResponse represents the response with a list of roles
type RolesResponse struct {
	Roles []Role `json:"roles"`
}

// GetRolePermissionsRequest represents the request to get permissions for a role
type GetRolePermissionsRequest struct {
	RoleID uuid.UUID `json:"-"`
}

// Validate validates the get role permissions request
func (r *GetRolePermissionsRequest) Validate(ctx context.Context) error {
	if r.RoleID == uuid.Nil {
		return fmt.Errorf("role_id is required")
	}
	return nil
}

// SetRolePermissionsRequest represents the request to set all permissions for a role
type SetRolePermissionsRequest struct {
	RoleID        uuid.UUID   `json:"-"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

// Validate validates the set role permissions request
func (r *SetRolePermissionsRequest) Validate(ctx context.Context) error {
	if r.RoleID == uuid.Nil {
		return fmt.Errorf("role_id is required")
	}
	return nil
}

// SetUserRolesRequest represents the request to set all roles for a user
type SetUserRolesRequest struct {
	UserID  uuid.UUID   `json:"-"`
	RoleIDs []uuid.UUID `json:"role_ids"`
}

// Validate validates the set user roles request
func (r *SetUserRolesRequest) Validate(ctx context.Context) error {
	if r.UserID == uuid.Nil {
		return fmt.Errorf("user_id is required")
	}
	return nil
}

// GetUserRolesRequest represents the request to get roles for a user
type GetUserRolesRequest struct {
	UserID uuid.UUID `json:"-"`
}

// Validate validates the get user roles request
func (r *GetUserRolesRequest) Validate(ctx context.Context) error {
	if r.UserID == uuid.Nil {
		return fmt.Errorf("user_id is required")
	}
	return nil
}

// EffectivePermission represents a direct permission assigned to a user
type EffectivePermission struct {
	Permission Permission       `json:"permission"`
	Effect     PermissionEffect `json:"effect"`
}

// DirectPermission represents a direct permission to set for a user
type DirectPermission struct {
	PermissionID uuid.UUID        `json:"permission_id"`
	Effect       PermissionEffect `json:"effect"`
}

// SetDirectPermissionsRequest represents the request to set all direct permissions for a user
type SetDirectPermissionsRequest struct {
	UserID      uuid.UUID          `json:"-"`
	Permissions []DirectPermission `json:"permissions"`
}

// Validate validates the set user permissions request
func (r *SetDirectPermissionsRequest) Validate(ctx context.Context) error {
	if r.UserID == uuid.Nil {
		return fmt.Errorf("user_id is required")
	}
	for _, perm := range r.Permissions {
		if perm.PermissionID == uuid.Nil {
			return fmt.Errorf("permission_id is required")
		}
	}
	return nil
}

// GetDirectPermissionsRequest represents the request to get direct permissions for a user
type GetDirectPermissionsRequest struct {
	UserID uuid.UUID `json:"-"`
}

// Validate validates the get user permissions request
func (r *GetDirectPermissionsRequest) Validate(ctx context.Context) error {
	if r.UserID == uuid.Nil {
		return fmt.Errorf("user_id is required")
	}
	return nil
}

// DirectPermissionsResponse represents the response with direct permissions for a user
type DirectPermissionsResponse struct {
	Permissions []EffectivePermission `json:"permissions"`
}
