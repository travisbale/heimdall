package http

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

// RBACHandler handles RBAC operations
type RBACHandler struct {
	rbacService rbacService
}

// NewRBACHandler creates a new RBAC handler
func NewRBACHandler(config *Config) *RBACHandler {
	return &RBACHandler{
		rbacService: config.RBACService,
	}
}

// ListPermissions retrieves all system permissions
func (h *RBACHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.rbacService.ListPermissions(r.Context())
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to list permissions"})
		return
	}

	sdkPermissions := make([]sdk.Permission, len(permissions))
	for i, perm := range permissions {
		sdkPermissions[i] = toSDKPermission(perm)
	}

	respondJSON(w, http.StatusOK, sdk.PermissionsResponse{
		Permissions: sdkPermissions,
	})
}

// CreateRole creates a new role
func (h *RBACHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var req sdk.CreateRoleRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	role, err := h.rbacService.CreateRole(r.Context(), req.Name, req.Description)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to create role"})
		return
	}

	respondJSON(w, http.StatusCreated, toSDKRole(role))
}

// GetRole retrieves a role by ID
func (h *RBACHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	req := sdk.GetRoleRequest{
		RoleID: parseUUID(chi.URLParam(r, "roleID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	role, err := h.rbacService.GetRole(r.Context(), req.RoleID)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrRoleNotFound):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "Role not found"})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to get role"})
		}
		return
	}

	respondJSON(w, http.StatusOK, toSDKRole(role))
}

// ListRoles retrieves all roles for the tenant
func (h *RBACHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.rbacService.ListRoles(r.Context())
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to list roles"})
		return
	}

	sdkRoles := make([]sdk.Role, len(roles))
	for i, role := range roles {
		sdkRoles[i] = toSDKRole(role)
	}

	respondJSON(w, http.StatusOK, sdk.RolesResponse{
		Roles: sdkRoles,
	})
}

// UpdateRole updates a role
func (h *RBACHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	var req sdk.UpdateRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid request body"})
		return
	}

	req.RoleID = parseUUID(chi.URLParam(r, "roleID"))
	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	role, err := h.rbacService.UpdateRole(r.Context(), req.RoleID, req.Name, req.Description)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrRoleNotFound):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "Role not found"})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to update role"})
		}
		return
	}

	respondJSON(w, http.StatusOK, toSDKRole(role))
}

// DeleteRole deletes a role
func (h *RBACHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	req := sdk.DeleteRoleRequest{
		RoleID: parseUUID(chi.URLParam(r, "roleID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	if err := h.rbacService.DeleteRole(r.Context(), req.RoleID); err != nil {
		switch {
		case errors.Is(err, auth.ErrRoleNotFound):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "Role not found"})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to delete role"})
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetRolePermissions retrieves all permissions for a role
func (h *RBACHandler) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
	req := sdk.GetRolePermissionsRequest{
		RoleID: parseUUID(chi.URLParam(r, "roleID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	permissions, err := h.rbacService.GetRolePermissions(r.Context(), req.RoleID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to get role permissions"})
		return
	}

	sdkPermissions := make([]sdk.Permission, len(permissions))
	for i, perm := range permissions {
		sdkPermissions[i] = toSDKPermission(perm)
	}

	respondJSON(w, http.StatusOK, sdk.PermissionsResponse{
		Permissions: sdkPermissions,
	})
}

// SetRolePermissions sets all permissions for a role (bulk update)
func (h *RBACHandler) SetRolePermissions(w http.ResponseWriter, r *http.Request) {
	var req sdk.SetRolePermissionsRequest
	if err := decodeJSON(r, &req); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid request body"})
		return
	}

	req.RoleID = parseUUID(chi.URLParam(r, "roleID"))
	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	if err := h.rbacService.SetRolePermissions(r.Context(), req.RoleID, req.PermissionIDs); err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to set role permissions"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SetUserRoles sets all roles for a user (replaces existing roles)
func (h *RBACHandler) SetUserRoles(w http.ResponseWriter, r *http.Request) {
	var req sdk.SetUserRolesRequest
	if err := decodeJSON(r, &req); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid request body"})
		return
	}

	req.UserID = parseUUID(chi.URLParam(r, "userID"))
	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	if err := h.rbacService.SetUserRoles(r.Context(), req.UserID, req.RoleIDs); err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to set user roles"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetUserRoles retrieves all roles for a user
func (h *RBACHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	req := sdk.GetUserRolesRequest{
		UserID: parseUUID(chi.URLParam(r, "userID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	roles, err := h.rbacService.GetUserRoles(r.Context(), req.UserID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to get user roles"})
		return
	}

	sdkRoles := make([]sdk.Role, len(roles))
	for i, role := range roles {
		sdkRoles[i] = toSDKRole(role)
	}

	respondJSON(w, http.StatusOK, sdk.RolesResponse{
		Roles: sdkRoles,
	})
}

// SetDirectPermissions sets all direct permissions for a user (replaces existing direct permissions)
func (h *RBACHandler) SetDirectPermissions(w http.ResponseWriter, r *http.Request) {
	var req sdk.SetDirectPermissionsRequest
	if err := decodeJSON(r, &req); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid request body"})
		return
	}

	req.UserID = parseUUID(chi.URLParam(r, "userID"))
	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	// Convert SDK permissions to auth permissions
	authPerms := make([]auth.DirectPermission, len(req.Permissions))
	for i, p := range req.Permissions {
		authPerms[i] = auth.DirectPermission{
			PermissionID: p.PermissionID,
			Effect:       p.Effect,
		}
	}

	if err := h.rbacService.SetDirectPermissions(r.Context(), req.UserID, authPerms); err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to set user permissions"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetDirectPermissions retrieves direct permissions assigned to a user
func (h *RBACHandler) GetDirectPermissions(w http.ResponseWriter, r *http.Request) {
	req := sdk.GetDirectPermissionsRequest{
		UserID: parseUUID(chi.URLParam(r, "userID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	permissions, err := h.rbacService.GetDirectPermissions(r.Context(), req.UserID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to get user permissions"})
		return
	}

	sdkPermissions := make([]sdk.EffectivePermission, len(permissions))
	for i, permission := range permissions {
		sdkPermissions[i] = sdk.EffectivePermission{
			Permission: toSDKPermission(permission.Permission),
			Effect:     permission.Effect,
		}
	}

	respondJSON(w, http.StatusOK, sdk.DirectPermissionsResponse{
		Permissions: sdkPermissions,
	})
}

// toSDKRole converts an auth.Role to sdk.Role
func toSDKRole(role *auth.Role) sdk.Role {
	return sdk.Role{
		ID:          role.ID,
		Name:        role.Name,
		Description: role.Description,
	}
}

// toSDKPermission converts an auth.Permission to sdk.Permission
func toSDKPermission(perm *auth.Permission) sdk.Permission {
	return sdk.Permission{
		ID:          perm.ID,
		Name:        perm.Name,
		Description: perm.Description,
	}
}
