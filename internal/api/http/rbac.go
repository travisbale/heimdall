package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
)

// ListPermissions retrieves all system permissions
func (r *Router) listPermissions(w http.ResponseWriter, req *http.Request) {
	permissions, err := r.RBACService.ListPermissions(req.Context())
	if err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to list permissions", err)
		return
	}

	sdkPermissions := make([]sdk.Permission, len(permissions))
	for i, perm := range permissions {
		sdkPermissions[i] = toSDKPermission(perm)
	}

	r.writeJSON(w, http.StatusOK, sdk.PermissionsResponse{
		Permissions: sdkPermissions,
	})
}

// CreateRole creates a new role
func (r *Router) createRole(w http.ResponseWriter, req *http.Request) {
	var body sdk.CreateRoleRequest
	if !r.decodeAndValidateJSON(w, req, &body) {
		return
	}

	role := &iam.Role{
		Name:        body.Name,
		Description: body.Description,
		MFARequired: body.MFARequired,
	}

	role, err := r.RBACService.CreateRole(req.Context(), role)
	if err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to create role", err)
		return
	}

	r.writeJSON(w, http.StatusCreated, toSDKRole(role))
}

// GetRole retrieves a role by ID
func (r *Router) getRole(w http.ResponseWriter, req *http.Request) {
	body := sdk.GetRoleRequest{
		RoleID: parseUUID(req.PathValue("roleID")),
	}

	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	role, err := r.RBACService.GetRole(req.Context(), body.RoleID)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrRoleNotFound):
			r.writeError(req.Context(), w, http.StatusNotFound, "Role not found", err)
		default:
			r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to get role", err)
		}
		return
	}

	r.writeJSON(w, http.StatusOK, toSDKRole(role))
}

// ListRoles retrieves all roles for the tenant
func (r *Router) listRoles(w http.ResponseWriter, req *http.Request) {
	roles, err := r.RBACService.ListRoles(req.Context())
	if err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to list roles", err)
		return
	}

	sdkRoles := make([]sdk.Role, len(roles))
	for i, role := range roles {
		sdkRoles[i] = toSDKRole(role)
	}

	r.writeJSON(w, http.StatusOK, sdk.RolesResponse{
		Roles: sdkRoles,
	})
}

// UpdateRole updates a role
func (r *Router) updateRole(w http.ResponseWriter, req *http.Request) {
	var body sdk.UpdateRoleRequest
	if err := decodeJSON(req, &body); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	body.RoleID = parseUUID(req.PathValue("roleID"))
	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Support partial updates using pointer fields
	params := iam.UpdateRoleParams{
		ID:          body.RoleID,
		Name:        body.Name,
		Description: body.Description,
		MFARequired: body.MFARequired,
	}

	role, err := r.RBACService.UpdateRole(req.Context(), params)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrRoleNotFound):
			r.writeError(req.Context(), w, http.StatusNotFound, "Role not found", err)
		default:
			r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to update role", err)
		}
		return
	}

	r.writeJSON(w, http.StatusOK, toSDKRole(role))
}

// DeleteRole deletes a role
func (r *Router) deleteRole(w http.ResponseWriter, req *http.Request) {
	body := sdk.DeleteRoleRequest{
		RoleID: parseUUID(req.PathValue("roleID")),
	}

	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	if err := r.RBACService.DeleteRole(req.Context(), body.RoleID); err != nil {
		switch {
		case errors.Is(err, iam.ErrRoleNotFound):
			r.writeError(req.Context(), w, http.StatusNotFound, "Role not found", err)
		default:
			r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to delete role", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetRolePermissions retrieves all permissions for a role
func (r *Router) getRolePermissions(w http.ResponseWriter, req *http.Request) {
	body := sdk.GetRolePermissionsRequest{
		RoleID: parseUUID(req.PathValue("roleID")),
	}

	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	permissions, err := r.RBACService.GetRolePermissions(req.Context(), body.RoleID)
	if err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to get role permissions", err)
		return
	}

	sdkPermissions := make([]sdk.Permission, len(permissions))
	for i, perm := range permissions {
		sdkPermissions[i] = toSDKPermission(perm)
	}

	r.writeJSON(w, http.StatusOK, sdk.PermissionsResponse{
		Permissions: sdkPermissions,
	})
}

// SetRolePermissions sets all permissions for a role (bulk update)
func (r *Router) setRolePermissions(w http.ResponseWriter, req *http.Request) {
	var body sdk.SetRolePermissionsRequest
	if err := decodeJSON(req, &body); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	body.RoleID = parseUUID(req.PathValue("roleID"))
	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	if err := r.RBACService.SetRolePermissions(req.Context(), body.RoleID, body.PermissionIDs); err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to set role permissions", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SetUserRoles sets all roles for a user (replaces existing roles)
func (r *Router) setUserRoles(w http.ResponseWriter, req *http.Request) {
	var body sdk.SetUserRolesRequest
	if err := decodeJSON(req, &body); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	body.UserID = parseUUID(req.PathValue("userID"))
	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	if err := r.RBACService.SetUserRoles(req.Context(), body.UserID, body.RoleIDs); err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to set user roles", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetUserRoles retrieves all roles for a user
func (r *Router) getUserRoles(w http.ResponseWriter, req *http.Request) {
	body := sdk.GetUserRolesRequest{
		UserID: parseUUID(req.PathValue("userID")),
	}

	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	roles, err := r.RBACService.GetUserRoles(req.Context(), body.UserID)
	if err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to get user roles", err)
		return
	}

	sdkRoles := make([]sdk.Role, len(roles))
	for i, role := range roles {
		sdkRoles[i] = toSDKRole(role)
	}

	r.writeJSON(w, http.StatusOK, sdk.RolesResponse{
		Roles: sdkRoles,
	})
}

// SetDirectPermissions sets all direct permissions for a user (replaces existing direct permissions)
func (r *Router) setDirectPermissions(w http.ResponseWriter, req *http.Request) {
	var body sdk.SetDirectPermissionsRequest
	if err := decodeJSON(req, &body); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	body.UserID = parseUUID(req.PathValue("userID"))
	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Convert SDK permissions to auth permissions
	authPerms := make([]iam.DirectPermission, len(body.Permissions))
	for i, p := range body.Permissions {
		authPerms[i] = iam.DirectPermission{
			PermissionID: p.PermissionID,
			Effect:       p.Effect,
		}
	}

	if err := r.RBACService.SetDirectPermissions(req.Context(), body.UserID, authPerms); err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to set user permissions", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetDirectPermissions retrieves direct permissions assigned to a user
func (r *Router) getDirectPermissions(w http.ResponseWriter, req *http.Request) {
	body := sdk.GetDirectPermissionsRequest{
		UserID: parseUUID(req.PathValue("userID")),
	}

	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	permissions, err := r.RBACService.GetDirectPermissions(req.Context(), body.UserID)
	if err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to get user permissions", err)
		return
	}

	sdkPermissions := make([]sdk.EffectivePermission, len(permissions))
	for i, permission := range permissions {
		sdkPermissions[i] = sdk.EffectivePermission{
			Permission: toSDKPermission(permission.Permission),
			Effect:     permission.Effect,
		}
	}

	r.writeJSON(w, http.StatusOK, sdk.DirectPermissionsResponse{
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
