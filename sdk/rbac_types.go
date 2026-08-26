package sdk

import (
	"context"

	"github.com/google/uuid"
)

// PermissionEffect is whether a permission allows or denies.
type PermissionEffect string

const (
	PermissionAllow PermissionEffect = "allow"
	PermissionDeny  PermissionEffect = "deny"
)

type Permission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

type PermissionsResponse struct {
	Permissions []Permission `json:"permissions"`
}

type Role struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	MFARequired bool      `json:"mfa_required"`
}

type CreateRoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	MFARequired bool   `json:"mfa_required"`
}

func (r *CreateRoleRequest) Validate(ctx context.Context) error {
	if err := validateRequired(r.Name, "name"); err != nil {
		return err
	}
	return validateRequired(r.Description, "description")
}

// UpdateRoleRequest updates a role. An omitted field keeps its stored value.
type UpdateRoleRequest struct {
	RoleID      uuid.UUID `json:"-"`
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	MFARequired *bool     `json:"mfa_required,omitempty"`
}

func (r *UpdateRoleRequest) Validate(ctx context.Context) error {
	if err := validateUUID(r.RoleID, "role_id"); err != nil {
		return err
	}
	if err := validateNotEmpty(r.Name, "name"); err != nil {
		return err
	}
	return validateNotEmpty(r.Description, "description")
}

type GetRoleRequest struct {
	RoleID uuid.UUID `json:"-"`
}

func (r *GetRoleRequest) Validate(ctx context.Context) error {
	return validateUUID(r.RoleID, "role_id")
}

type DeleteRoleRequest struct {
	RoleID uuid.UUID `json:"-"`
}

func (r *DeleteRoleRequest) Validate(ctx context.Context) error {
	return validateUUID(r.RoleID, "role_id")
}

type RolesResponse struct {
	Roles []Role `json:"roles"`
}

type GetRolePermissionsRequest struct {
	RoleID uuid.UUID `json:"-"`
}

func (r *GetRolePermissionsRequest) Validate(ctx context.Context) error {
	return validateUUID(r.RoleID, "role_id")
}

type SetRolePermissionsRequest struct {
	RoleID        uuid.UUID   `json:"-"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

func (r *SetRolePermissionsRequest) Validate(ctx context.Context) error {
	return validateUUID(r.RoleID, "role_id")
}

type SetUserRolesRequest struct {
	UserID  uuid.UUID   `json:"-"`
	RoleIDs []uuid.UUID `json:"role_ids"`
}

func (r *SetUserRolesRequest) Validate(ctx context.Context) error {
	return validateUUID(r.UserID, "user_id")
}

type GetUserRolesRequest struct {
	UserID uuid.UUID `json:"-"`
}

func (r *GetUserRolesRequest) Validate(ctx context.Context) error {
	return validateUUID(r.UserID, "user_id")
}

// EffectivePermission is a permission assigned to a user directly, bypassing roles.
type EffectivePermission struct {
	Permission Permission       `json:"permission"`
	Effect     PermissionEffect `json:"effect"`
}

// DirectPermission is one entry in a replacement set of a user's direct permissions.
type DirectPermission struct {
	PermissionID uuid.UUID        `json:"permission_id"`
	Effect       PermissionEffect `json:"effect"`
}

type SetDirectPermissionsRequest struct {
	UserID      uuid.UUID          `json:"-"`
	Permissions []DirectPermission `json:"permissions"`
}

func (r *SetDirectPermissionsRequest) Validate(ctx context.Context) error {
	if err := validateUUID(r.UserID, "user_id"); err != nil {
		return err
	}
	for _, perm := range r.Permissions {
		if err := validateUUID(perm.PermissionID, "permission_id"); err != nil {
			return err
		}
	}
	return nil
}

type GetDirectPermissionsRequest struct {
	UserID uuid.UUID `json:"-"`
}

func (r *GetDirectPermissionsRequest) Validate(ctx context.Context) error {
	return validateUUID(r.UserID, "user_id")
}

type DirectPermissionsResponse struct {
	Permissions []EffectivePermission `json:"permissions"`
}
