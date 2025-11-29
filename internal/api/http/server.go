package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/clog"
	"github.com/travisbale/knowhere/identity"
	"github.com/travisbale/knowhere/jwt"
)

type Server struct {
	*http.Server
}

func NewServer(config *Config) *Server {
	// Create domain handlers
	healthHandler := NewHealthHandler(config)
	authHandler := NewAuthHandler(config)
	registrationHandler := NewRegistrationHandler(config)
	passwordResetHandler := NewPasswordResetHandler(config)
	oidcAuthHandler := NewOIDCAuthHandler(config)
	oidcProvidersHandler := NewOIDCProvidersHandler(config)
	rbacHandler := NewRBACHandler(config)
	mfaHandler := NewMFAHandler(config)
	sessionsHandler := NewSessionsHandler(config)

	// Create JWT middleware
	jwtMiddleware := jwt.NewHTTPMiddleware(config.JWTValidator)
	auth := jwtMiddleware.Authenticate
	require := jwtMiddleware.RequireScope

	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.Recoverer)
	r.Use(identity.RequestID)
	r.Use(identity.ClientIP(config.TrustedProxyMode))
	r.Use(identity.UserAgent)

	// Set the logging middleware last so context is enriched
	r.Use(clog.Middleware(config.Logger))

	// CORS enabled only when origins specified (browser-based clients require this)
	if len(config.CORSAllowedOrigins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   config.CORSAllowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: true,
			MaxAge:           300, // Maximum value not ignored by major browsers
		}))
	}

	// Health check endpoint (nginx internal, no auth required, no rate limit)
	r.Head(sdk.RouteHealth, healthHandler.HandleHealth)

	// Supported OAuth provider types (public, no auth required, no rate limit)
	r.Get(sdk.RouteV1OAuthSupportedTypes, ListSupportedProviders)

	// Moderate rate limit for registration endpoints (less sensitive than authentication)
	r.Group(func(r chi.Router) {
		if config.Environment != "test" {
			r.Use(newRateLimitMiddleware(ModerateRateLimit))
		}

		r.Post(sdk.RouteV1Register, registrationHandler.Register)
		r.Post(sdk.RouteV1VerifyEmail, registrationHandler.ConfirmRegistration)
	})

	// Strict rate limit for authentication endpoints (prevent brute force attacks)
	r.Group(func(r chi.Router) {
		if config.Environment != "test" {
			r.Use(newRateLimitMiddleware(StrictRateLimit))
		}

		r.Post(sdk.RouteV1Login, authHandler.Login)
		r.Post(sdk.RouteV1Refresh, authHandler.RefreshToken)
		r.Delete(sdk.RouteV1Refresh, authHandler.Logout)

		r.Post(sdk.RouteV1ForgotPassword, passwordResetHandler.ForgotPassword)
		r.Post(sdk.RouteV1ResetPassword, passwordResetHandler.ResetPassword)

		r.Post(sdk.RouteV1OAuthLogin, oidcAuthHandler.Login)
		r.Post(sdk.RouteV1SSOLogin, oidcAuthHandler.SSOLogin)
		r.Get(sdk.RouteV1OAuthCallback, oidcAuthHandler.Callback)

		r.Post(sdk.RouteV1MFAVerify, mfaHandler.Login)

		// Required MFA setup (unauthenticated, uses setup token from login response)
		r.Post(sdk.RouteV1MFARequiredSetup, mfaHandler.RequiredSetup)
		r.Post(sdk.RouteV1MFARequiredEnable, mfaHandler.RequiredEnable)
	})

	// OIDC provider management
	r.With(require(iam.ScopeOIDCCreate)).Post(sdk.RouteV1OAuthProviders, oidcProvidersHandler.CreateOIDCProvider)
	r.With(require(iam.ScopeOIDCRead)).Get(sdk.RouteV1OAuthProviders, oidcProvidersHandler.ListOIDCProviders)
	r.With(require(iam.ScopeOIDCRead)).Get(sdk.RouteV1OAuthProvider, oidcProvidersHandler.GetOIDCProvider)
	r.With(require(iam.ScopeOIDCUpdate)).Put(sdk.RouteV1OAuthProvider, oidcProvidersHandler.UpdateOIDCProvider)
	r.With(require(iam.ScopeOIDCDelete)).Delete(sdk.RouteV1OAuthProvider, oidcProvidersHandler.DeleteOIDCProvider)

	// RBAC - Permissions
	r.With(require(iam.ScopeRoleRead)).Get(sdk.RouteV1Permissions, rbacHandler.ListPermissions)

	// RBAC - Roles
	r.With(require(iam.ScopeRoleCreate)).Post(sdk.RouteV1Roles, rbacHandler.CreateRole)
	r.With(require(iam.ScopeRoleRead)).Get(sdk.RouteV1Roles, rbacHandler.ListRoles)
	r.With(require(iam.ScopeRoleRead)).Get(sdk.RouteV1Role, rbacHandler.GetRole)
	r.With(require(iam.ScopeRoleUpdate)).Put(sdk.RouteV1Role, rbacHandler.UpdateRole)
	r.With(require(iam.ScopeRoleDelete)).Delete(sdk.RouteV1Role, rbacHandler.DeleteRole)

	// RBAC - Role permissions
	r.With(require(iam.ScopeRoleRead)).Get(sdk.RouteV1RolePermissions, rbacHandler.GetRolePermissions)
	r.With(require(iam.ScopeRoleUpdate)).Put(sdk.RouteV1RolePermissions, rbacHandler.SetRolePermissions)

	// RBAC - User roles
	r.With(require(iam.ScopeUserRead)).Get(sdk.RouteV1UserRoles, rbacHandler.GetUserRoles)
	r.With(require(iam.ScopeUserAssign)).Put(sdk.RouteV1UserRoles, rbacHandler.SetUserRoles)

	// RBAC - User direct permissions
	r.With(require(iam.ScopeUserRead)).Get(sdk.RouteV1UserPermissions, rbacHandler.GetDirectPermissions)
	r.With(require(iam.ScopeUserAssign)).Put(sdk.RouteV1UserPermissions, rbacHandler.SetDirectPermissions)

	// MFA management endpoints
	r.With(auth).Post(sdk.RouteV1MFASetup, mfaHandler.Setup)
	r.With(auth).Post(sdk.RouteV1MFAEnable, mfaHandler.Enable)
	r.With(auth).Delete(sdk.RouteV1MFADisable, mfaHandler.Disable)
	r.With(auth).Get(sdk.RouteV1MFAStatus, mfaHandler.Status)
	r.With(auth).Post(sdk.RouteV1MFARegenerateCodes, mfaHandler.RegenerateCodes)

	// Session management endpoints
	r.With(auth).Get(sdk.RouteV1Sessions, sessionsHandler.ListSessions)
	r.With(auth).Delete(sdk.RouteV1Sessions, sessionsHandler.RevokeAllSessions)
	r.With(auth).Delete(sdk.RouteV1SessionByID, sessionsHandler.RevokeSession)

	return &Server{
		&http.Server{
			Addr:              config.Address,
			Handler:           r,
			ReadHeaderTimeout: 5 * time.Second, // Prevents Slowloris attacks
		},
	}
}
