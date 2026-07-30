package iam

import "github.com/travisbale/knowhere/jwt"

// Scope is an alias for jwt.Scope
type Scope = jwt.Scope

// JWTClaims is an alias for jwt.Claims
type JWTClaims = jwt.Claims

// System-wide scopes for Heimdall authentication and authorization service
const (
	// User management scopes
	ScopeUserCreate Scope = "heimdall:user:create" // Create new user accounts
	ScopeUserRead   Scope = "heimdall:user:read"   // View user information and their role/permission assignments
	ScopeUserUpdate Scope = "heimdall:user:update" // Update user profile (email, name, status)
	ScopeUserDelete Scope = "heimdall:user:delete" // Delete user accounts
	ScopeUserAssign Scope = "heimdall:user:assign" // Assign roles and permissions to users

	// Role management scopes
	ScopeRoleCreate Scope = "heimdall:role:create" // Create new roles
	ScopeRoleRead   Scope = "heimdall:role:read"   // View roles and their permissions
	ScopeRoleUpdate Scope = "heimdall:role:update" // Update roles and their permission assignments
	ScopeRoleDelete Scope = "heimdall:role:delete" // Delete roles

	// OIDC provider management scopes
	ScopeOIDCCreate Scope = "heimdall:oidc:create" // Create OIDC/SSO provider configurations
	ScopeOIDCRead   Scope = "heimdall:oidc:read"   // View OIDC/SSO provider configurations
	ScopeOIDCUpdate Scope = "heimdall:oidc:update" // Update OIDC/SSO provider settings
	ScopeOIDCDelete Scope = "heimdall:oidc:delete" // Delete OIDC/SSO provider configurations
)

// AllScopes is the canonical list of every scope Heimdall defines. The seed
// migration must insert exactly these names; a test asserts the two agree.
var AllScopes = []Scope{
	ScopeUserCreate,
	ScopeUserRead,
	ScopeUserUpdate,
	ScopeUserDelete,
	ScopeUserAssign,

	ScopeRoleCreate,
	ScopeRoleRead,
	ScopeRoleUpdate,
	ScopeRoleDelete,

	ScopeOIDCCreate,
	ScopeOIDCRead,
	ScopeOIDCUpdate,
	ScopeOIDCDelete,
}
