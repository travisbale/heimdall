package sdk

// API routes for the heimdall authentication service
const (
	RouteHealth = "/healthz"

	// API routes
	RouteV1Login              = "/v1/login"
	RouteV1Logout             = "/v1/logout"
	RouteV1Refresh            = "/v1/refresh"
	RouteV1Register           = "/v1/register"
	RouteV1VerifyEmail        = "/v1/verify-email"
	RouteV1ResendVerification = "/v1/resend-verification"
	RouteV1ForgotPassword     = "/v1/forgot-password"
	RouteV1ResetPassword      = "/v1/reset-password"

	// OAuth/SSO routes
	RouteV1OAuthLogin    = "/v1/oauth/login" // Individual OAuth login
	RouteV1SSOLogin      = "/v1/sso/login"   // Corporate SSO login
	RouteV1OAuthLinks    = "/v1/oauth/links"
	RouteV1OAuthLink     = "/v1/oauth/links/{providerID}"
	RouteV1OAuthCallback = "/v1/oauth/callback"

	// OAuth provider management routes
	RouteV1OAuthProviders      = "/v1/oauth/providers"
	RouteV1OAuthProvider       = "/v1/oauth/providers/{providerID}"
	RouteV1OAuthSupportedTypes = "/v1/oauth/supported-types" // Public: list supported provider types
)
