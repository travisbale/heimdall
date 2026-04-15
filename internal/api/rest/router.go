package rest

import (
	"context"
	"log/slog"
	"net/http"
	"sync"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/identity"
	"github.com/travisbale/knowhere/jwt"
	"github.com/ulule/limiter/v3"
)

type database interface {
	Health(ctx context.Context) error
}

type jwtValidator interface {
	ValidateToken(token string) (*iam.JWTClaims, error)
}

// Router holds all HTTP handler dependencies in a single struct.
// Implements http.Handler — routes and middleware are initialized on first request.
type Router struct {
	DB                  database
	AuthService         *iam.AuthService
	UserService         *iam.UserService
	PasswordService     *iam.PasswordService
	MFAService          *iam.MFAService
	OIDCAuthService     *iam.OIDCAuthService
	OIDCProviderService *iam.OIDCProviderService
	RBACService         *iam.RBACService
	SessionService      *iam.SessionService
	JWTValidator        jwtValidator
	SecureCookies       bool
	Environment         string
	TrustedProxyMode    bool
	CORSAllowedOrigins  []string
	Logger              *slog.Logger

	once          sync.Once
	jwtMiddleware *jwt.HTTPMiddleware
	handler       http.Handler
}

// ServeHTTP implements http.Handler. Routes and middleware are initialized on first request.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.once.Do(r.init)
	r.handler.ServeHTTP(w, req)
}

func (r *Router) init() {
	r.jwtMiddleware = jwt.NewHTTPMiddleware(r.JWTValidator)

	mux := http.NewServeMux()
	r.registerRoutes(mux)

	// Build global middleware chain
	var handler http.Handler = mux
	handler = identity.UserAgent(handler)
	handler = identity.ClientIP(r.TrustedProxyMode)(handler)
	handler = identity.RequestID(handler)
	handler = recoverMiddleware(handler)
	if len(r.CORSAllowedOrigins) > 0 {
		handler = corsMiddleware(r.CORSAllowedOrigins)(handler)
	}
	r.handler = handler
}

// registerRoutes configures all HTTP routes with their handlers and middleware
func (r *Router) registerRoutes(mux *http.ServeMux) {
	public := func(method, route string, handler http.HandlerFunc) {
		mux.HandleFunc(method+" "+route, handler)
	}
	limit := func(rate limiter.Rate, method, route string, handler http.HandlerFunc) {
		if r.Environment != "test" {
			handler = rateLimitMiddleware(rate, handler)
		}
		mux.HandleFunc(method+" "+route, handler)
	}
	auth := func(method, route string, handler http.HandlerFunc) {
		mux.HandleFunc(method+" "+route, r.jwtMiddleware.Authenticate(handler))
	}
	require := func(method, route string, scope iam.Scope, handler http.HandlerFunc) {
		mux.HandleFunc(method+" "+route, r.jwtMiddleware.RequireScope(scope, handler))
	}

	// Public endpoints
	public("HEAD", sdk.RouteHealth, r.handleHealth)
	public("GET", sdk.RouteV1OAuthSupportedTypes, r.listSupportedProviders)

	// Registration (moderate rate limit)
	limit(moderateRateLimit, "POST", sdk.RouteV1Register, r.register)
	limit(moderateRateLimit, "POST", sdk.RouteV1VerifyEmail, r.confirmRegistration)

	// Authentication (strict rate limit)
	limit(strictRateLimit, "POST", sdk.RouteV1Login, r.login)
	limit(strictRateLimit, "POST", sdk.RouteV1Refresh, r.refreshToken)
	limit(strictRateLimit, "DELETE", sdk.RouteV1Refresh, r.logout)
	limit(strictRateLimit, "POST", sdk.RouteV1ForgotPassword, r.forgotPassword)
	limit(strictRateLimit, "POST", sdk.RouteV1ResetPassword, r.resetPassword)
	limit(strictRateLimit, "POST", sdk.RouteV1OAuthLogin, r.oauthLogin)
	limit(strictRateLimit, "POST", sdk.RouteV1SSOLogin, r.ssoLogin)
	limit(strictRateLimit, "GET", sdk.RouteV1OAuthCallback, r.oauthCallback)
	limit(strictRateLimit, "POST", sdk.RouteV1MFAVerify, r.mfaLogin)
	limit(strictRateLimit, "POST", sdk.RouteV1MFARequiredSetup, r.requiredSetup)
	limit(strictRateLimit, "POST", sdk.RouteV1MFARequiredEnable, r.requiredEnable)

	// OIDC provider management
	require("POST", sdk.RouteV1OAuthProviders, iam.ScopeOIDCCreate, r.createOIDCProvider)
	require("GET", sdk.RouteV1OAuthProviders, iam.ScopeOIDCRead, r.listOIDCProviders)
	require("GET", sdk.RouteV1OAuthProvider, iam.ScopeOIDCRead, r.getOIDCProvider)
	require("PUT", sdk.RouteV1OAuthProvider, iam.ScopeOIDCUpdate, r.updateOIDCProvider)
	require("DELETE", sdk.RouteV1OAuthProvider, iam.ScopeOIDCDelete, r.deleteOIDCProvider)

	// RBAC
	require("GET", sdk.RouteV1Permissions, iam.ScopeRoleRead, r.listPermissions)
	require("POST", sdk.RouteV1Roles, iam.ScopeRoleCreate, r.createRole)
	require("GET", sdk.RouteV1Roles, iam.ScopeRoleRead, r.listRoles)
	require("GET", sdk.RouteV1Role, iam.ScopeRoleRead, r.getRole)
	require("PUT", sdk.RouteV1Role, iam.ScopeRoleUpdate, r.updateRole)
	require("DELETE", sdk.RouteV1Role, iam.ScopeRoleDelete, r.deleteRole)
	require("GET", sdk.RouteV1RolePermissions, iam.ScopeRoleRead, r.getRolePermissions)
	require("PUT", sdk.RouteV1RolePermissions, iam.ScopeRoleUpdate, r.setRolePermissions)
	require("GET", sdk.RouteV1UserRoles, iam.ScopeUserRead, r.getUserRoles)
	require("PUT", sdk.RouteV1UserRoles, iam.ScopeUserAssign, r.setUserRoles)
	require("GET", sdk.RouteV1UserPermissions, iam.ScopeUserRead, r.getDirectPermissions)
	require("PUT", sdk.RouteV1UserPermissions, iam.ScopeUserAssign, r.setDirectPermissions)

	// User profile
	auth("GET", sdk.RouteV1Me, r.getMe)

	// MFA management
	auth("POST", sdk.RouteV1MFASetup, r.setupMFA)
	auth("POST", sdk.RouteV1MFAEnable, r.enableMFA)
	auth("DELETE", sdk.RouteV1MFADisable, r.disableMFA)
	auth("GET", sdk.RouteV1MFAStatus, r.mfaStatus)
	auth("POST", sdk.RouteV1MFARegenerateCodes, r.regenerateCodes)

	// Session management
	auth("GET", sdk.RouteV1Sessions, r.listSessions)
	auth("DELETE", sdk.RouteV1Sessions, r.revokeAllSessions)
	auth("DELETE", sdk.RouteV1SessionByID, r.revokeSession)
}
