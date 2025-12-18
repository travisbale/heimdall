package http

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
)

// RBACHandler handles RBAC operations
type RBACHandler struct {
	RBACService rbacService
}

// ListPermissions retrieves all system permissions
func (h *RBACHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.RBACService.ListPermissions(r.Context())
	if err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to list permissions", err)
		return
	}

	sdkPermissions := make([]sdk.Permission, len(permissions))
	for i, perm := range permissions {
		sdkPermissions[i] = toSDKPermission(perm)
	}

	api.RespondJSON(w, http.StatusOK, sdk.PermissionsResponse{
		Permissions: sdkPermissions,
	})
}

// CreateRole creates a new role
func (h *RBACHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var req sdk.CreateRoleRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	role := &iam.Role{
		Name:        req.Name,
		Description: req.Description,
		MFARequired: req.MFARequired,
	}

	role, err := h.RBACService.CreateRole(r.Context(), role)
	if err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to create role", err)
		return
	}

	api.RespondJSON(w, http.StatusCreated, toSDKRole(role))
}

// GetRole retrieves a role by ID
func (h *RBACHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	req := sdk.GetRoleRequest{
		RoleID: api.ParseUUID(chi.URLParam(r, "roleID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	role, err := h.RBACService.GetRole(r.Context(), req.RoleID)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrRoleNotFound):
			api.RespondError(w, http.StatusNotFound, "Role not found", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to get role", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusOK, toSDKRole(role))
}

// ListRoles retrieves all roles for the tenant
func (h *RBACHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.RBACService.ListRoles(r.Context())
	if err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to list roles", err)
		return
	}

	sdkRoles := make([]sdk.Role, len(roles))
	for i, role := range roles {
		sdkRoles[i] = toSDKRole(role)
	}

	api.RespondJSON(w, http.StatusOK, sdk.RolesResponse{
		Roles: sdkRoles,
	})
}

// UpdateRole updates a role
func (h *RBACHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	var req sdk.UpdateRoleRequest
	if err := api.DecodeJSON(r, &req); err != nil {
		api.RespondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	req.RoleID = api.ParseUUID(chi.URLParam(r, "roleID"))
	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Support partial updates using pointer fields
	params := iam.UpdateRoleParams{
		ID:          req.RoleID,
		Name:        req.Name,
		Description: req.Description,
		MFARequired: req.MFARequired,
	}

	role, err := h.RBACService.UpdateRole(r.Context(), params)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrRoleNotFound):
			api.RespondError(w, http.StatusNotFound, "Role not found", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to update role", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusOK, toSDKRole(role))
}

// DeleteRole deletes a role
func (h *RBACHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	req := sdk.DeleteRoleRequest{
		RoleID: api.ParseUUID(chi.URLParam(r, "roleID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	if err := h.RBACService.DeleteRole(r.Context(), req.RoleID); err != nil {
		switch {
		case errors.Is(err, iam.ErrRoleNotFound):
			api.RespondError(w, http.StatusNotFound, "Role not found", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to delete role", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetRolePermissions retrieves all permissions for a role
func (h *RBACHandler) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
	req := sdk.GetRolePermissionsRequest{
		RoleID: api.ParseUUID(chi.URLParam(r, "roleID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	permissions, err := h.RBACService.GetRolePermissions(r.Context(), req.RoleID)
	if err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to get role permissions", err)
		return
	}

	sdkPermissions := make([]sdk.Permission, len(permissions))
	for i, perm := range permissions {
		sdkPermissions[i] = toSDKPermission(perm)
	}

	api.RespondJSON(w, http.StatusOK, sdk.PermissionsResponse{
		Permissions: sdkPermissions,
	})
}

// SetRolePermissions sets all permissions for a role (bulk update)
func (h *RBACHandler) SetRolePermissions(w http.ResponseWriter, r *http.Request) {
	var req sdk.SetRolePermissionsRequest
	if err := api.DecodeJSON(r, &req); err != nil {
		api.RespondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	req.RoleID = api.ParseUUID(chi.URLParam(r, "roleID"))
	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	if err := h.RBACService.SetRolePermissions(r.Context(), req.RoleID, req.PermissionIDs); err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to set role permissions", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SetUserRoles sets all roles for a user (replaces existing roles)
func (h *RBACHandler) SetUserRoles(w http.ResponseWriter, r *http.Request) {
	var req sdk.SetUserRolesRequest
	if err := api.DecodeJSON(r, &req); err != nil {
		api.RespondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	req.UserID = api.ParseUUID(chi.URLParam(r, "userID"))
	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	if err := h.RBACService.SetUserRoles(r.Context(), req.UserID, req.RoleIDs); err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to set user roles", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetUserRoles retrieves all roles for a user
func (h *RBACHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	req := sdk.GetUserRolesRequest{
		UserID: api.ParseUUID(chi.URLParam(r, "userID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	roles, err := h.RBACService.GetUserRoles(r.Context(), req.UserID)
	if err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to get user roles", err)
		return
	}

	sdkRoles := make([]sdk.Role, len(roles))
	for i, role := range roles {
		sdkRoles[i] = toSDKRole(role)
	}

	api.RespondJSON(w, http.StatusOK, sdk.RolesResponse{
		Roles: sdkRoles,
	})
}

// SetDirectPermissions sets all direct permissions for a user (replaces existing direct permissions)
func (h *RBACHandler) SetDirectPermissions(w http.ResponseWriter, r *http.Request) {
	var req sdk.SetDirectPermissionsRequest
	if err := api.DecodeJSON(r, &req); err != nil {
		api.RespondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	req.UserID = api.ParseUUID(chi.URLParam(r, "userID"))
	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Convert SDK permissions to auth permissions
	authPerms := make([]iam.DirectPermission, len(req.Permissions))
	for i, p := range req.Permissions {
		authPerms[i] = iam.DirectPermission{
			PermissionID: p.PermissionID,
			Effect:       p.Effect,
		}
	}

	if err := h.RBACService.SetDirectPermissions(r.Context(), req.UserID, authPerms); err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to set user permissions", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetDirectPermissions retrieves direct permissions assigned to a user
func (h *RBACHandler) GetDirectPermissions(w http.ResponseWriter, r *http.Request) {
	req := sdk.GetDirectPermissionsRequest{
		UserID: api.ParseUUID(chi.URLParam(r, "userID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	permissions, err := h.RBACService.GetDirectPermissions(r.Context(), req.UserID)
	if err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to get user permissions", err)
		return
	}

	sdkPermissions := make([]sdk.EffectivePermission, len(permissions))
	for i, permission := range permissions {
		sdkPermissions[i] = sdk.EffectivePermission{
			Permission: toSDKPermission(permission.Permission),
			Effect:     permission.Effect,
		}
	}

	api.RespondJSON(w, http.StatusOK, sdk.DirectPermissionsResponse{
		Permissions: sdkPermissions,
	})
}

// toSDKRole converts an iam.Role to sdk.Role
func toSDKRole(role *iam.Role) sdk.Role {
	return sdk.Role{
		ID:          role.ID,
		Name:        role.Name,
		Description: role.Description,
		MFARequired: role.MFARequired,
	}
}

// toSDKPermission converts an iam.Permission to sdk.Permission
func toSDKPermission(perm *iam.Permission) sdk.Permission {
	return sdk.Permission{
		ID:          perm.ID,
		Name:        perm.Name,
		Description: perm.Description,
	}
}
