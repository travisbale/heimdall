package sdk

// API routes for the heimdall authentication service
const (
	RouteHealth = "/healthz"

	// v1 API routes
	RouteV1Login              = "/v1/login"
	RouteV1Logout             = "/v1/logout"
	RouteV1Refresh            = "/v1/refresh"
	RouteV1Register           = "/v1/register"
	RouteV1VerifyEmail        = "/v1/verify-email"
	RouteV1ResendVerification = "/v1/resend-verification"
	RouteV1ForgotPassword     = "/v1/forgot-password"
	RouteV1ResetPassword      = "/v1/reset-password"
)
