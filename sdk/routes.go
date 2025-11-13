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
)
