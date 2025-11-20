package sdk

// Scope represents a system permission identifier used in JWT tokens and authorization
type Scope string

// System-wide scopes for Heimdall authentication and authorization service
const (
	// User management scopes
	ScopeUserCreate Scope = "user:create" // Create new user accounts
	ScopeUserRead   Scope = "user:read"   // View user information and their role/permission assignments
	ScopeUserUpdate Scope = "user:update" // Update user profile (email, name, status)
	ScopeUserDelete Scope = "user:delete" // Delete user accounts
	ScopeUserAssign Scope = "user:assign" // Assign roles and permissions to users

	// Role management scopes
	ScopeRoleCreate Scope = "role:create" // Create new roles
	ScopeRoleRead   Scope = "role:read"   // View roles and their permissions
	ScopeRoleUpdate Scope = "role:update" // Update roles and their permission assignments
	ScopeRoleDelete Scope = "role:delete" // Delete roles

	// OIDC provider management scopes
	ScopeOIDCCreate Scope = "oidc:create" // Create OIDC/SSO provider configurations
	ScopeOIDCRead   Scope = "oidc:read"   // View OIDC/SSO provider configurations
	ScopeOIDCUpdate Scope = "oidc:update" // Update OIDC/SSO provider settings
	ScopeOIDCDelete Scope = "oidc:delete" // Delete OIDC/SSO provider configurations

	// Authentication state scopes
	ScopeAuthenticated Scope = "authenticated" // User has completed full authentication (not pending MFA)
	ScopeMFALogin      Scope = "mfa:login"     // Temporary scope for MFA verification (partial auth)
)

// String returns the scope as a string
func (s Scope) String() string {
	return string(s)
}
