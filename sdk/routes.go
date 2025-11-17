package sdk

// API route constants shared between server and SDK clients
const (
	RouteHealth = "/healthz"

	// Authentication endpoints
	RouteV1Login          = "/v1/login"
	RouteV1Logout         = "/v1/logout"
	RouteV1Refresh        = "/v1/refresh"
	RouteV1Register       = "/v1/register"
	RouteV1VerifyEmail    = "/v1/verify-email"
	RouteV1ForgotPassword = "/v1/forgot-password"
	RouteV1ResetPassword  = "/v1/reset-password"

	// OAuth/SSO endpoints
	RouteV1OAuthLogin    = "/v1/oauth/login"    // Individual OAuth (Google, GitHub, etc.)
	RouteV1SSOLogin      = "/v1/sso/login"      // Corporate SSO (domain-based routing)
	RouteV1OAuthCallback = "/v1/oauth/callback" // OAuth callback handler

	// OAuth provider configuration (authenticated)
	RouteV1OAuthProviders      = "/v1/oauth/providers"
	RouteV1OAuthProvider       = "/v1/oauth/providers/{providerID}"
	RouteV1OAuthSupportedTypes = "/v1/oauth/supported-types" // Public endpoint

	// RBAC endpoints (authenticated)
	RouteV1Permissions = "/v1/permissions" // List all system permissions

	// Role management
	RouteV1Roles = "/v1/roles"
	RouteV1Role  = "/v1/roles/{roleID}"

	// Role permissions
	RouteV1RolePermissions = "/v1/roles/{roleID}/permissions"
	RouteV1RolePermission  = "/v1/roles/{roleID}/permissions/{permissionID}"

	// User roles
	RouteV1UserRoles = "/v1/users/{userID}/roles"
	RouteV1UserRole  = "/v1/users/{userID}/roles/{roleID}"

	// User direct permissions
	RouteV1UserPermissions = "/v1/users/{userID}/permissions"
	RouteV1UserPermission  = "/v1/users/{userID}/permissions/{permissionID}"
)
