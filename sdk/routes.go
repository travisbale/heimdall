package sdk

// API route constants shared between server and SDK clients
const (
	RouteHealth = "/healthz"

	// Authentication endpoints
	RouteV1Login          = "/v1/login"
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

	// User endpoints
	RouteV1Me = "/v1/users/me"

	// User roles
	RouteV1UserRoles = "/v1/users/{userID}/roles"
	RouteV1UserRole  = "/v1/users/{userID}/roles/{roleID}"

	// User direct permissions
	RouteV1UserPermissions = "/v1/users/{userID}/permissions"
	RouteV1UserPermission  = "/v1/users/{userID}/permissions/{permissionID}"

	// MFA endpoints
	RouteV1MFASetup           = "/v1/mfa/setup"                   // Start MFA setup (authenticated)
	RouteV1MFAEnable          = "/v1/mfa/enable"                  // Verify and enable MFA (authenticated)
	RouteV1MFAVerify          = "/v1/mfa/verify"                  // Verify MFA code during login
	RouteV1MFADisable         = "/v1/mfa/disable"                 // Disable MFA (authenticated)
	RouteV1MFAStatus          = "/v1/mfa/status"                  // Get MFA status (authenticated)
	RouteV1MFARegenerateCodes = "/v1/mfa/backup-codes/regenerate" // Regenerate backup codes (authenticated)

	// Required MFA setup endpoints (unauthenticated, uses setup token)
	RouteV1MFARequiredSetup  = "/v1/mfa/required-setup"  // Start MFA setup when role requires it
	RouteV1MFARequiredEnable = "/v1/mfa/required-enable" // Enable MFA and complete login

	// Session management endpoints (authenticated)
	RouteV1Sessions    = "/v1/sessions"             // List active sessions, revoke all
	RouteV1SessionByID = "/v1/sessions/{sessionID}" // Revoke specific session
)
