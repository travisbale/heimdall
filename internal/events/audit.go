package events

// Audit events are user-facing events that are sent to uatu for display in audit logs.
// These represent completed actions that users would want to see in their activity history.

// Authentication Audit Events
const (
	LoginSucceeded = "login_succeeded"
)

// RBAC Audit Events
const (
	RoleCreated            = "role_created"
	RoleUpdated            = "role_updated"
	RoleDeleted            = "role_deleted"
	RolePermissionsUpdated = "role_permissions_updated"
	UserRolesUpdated       = "user_roles_updated"
	UserPermissionsUpdated = "user_permissions_updated"
)

// OIDC Provider Audit Events
const (
	OIDCProviderCreated = "oidc_provider_created"
	OIDCProviderUpdated = "oidc_provider_updated"
	OIDCProviderDeleted = "oidc_provider_deleted"
)
