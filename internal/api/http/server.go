package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/travisbale/heimdall/http/middleware"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

type Server struct {
	*http.Server
}

func NewServer(config *Config) *Server {
	config.TokenService = NewTokenService(config.SessionService, config.SecureCookies())

	// Create domain handlers
	healthHandler := NewHealthHandler(config)
	authHandler := NewAuthHandler(config)
	registrationHandler := NewRegistrationHandler(config)
	passwordResetHandler := NewPasswordResetHandler(config)
	oidcAuthHandler := NewOIDCAuthHandler(config)
	oidcProvidersHandler := NewOIDCProvidersHandler(config)
	rbacHandler := NewRBACHandler(config)
	mfaHandler := NewMFAHandler(config)

	// Create JWT middleware
	jwtMiddleware := jwt.NewHTTPMiddleware(config.JWTService)
	require := jwtMiddleware.RequireScope

	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RequestID)
	r.Use(middleware.ClientIP(config.TrustedProxyMode))
	r.Use(middleware.Logger(config.Logger))

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
		r.Post(sdk.RouteV1Logout, authHandler.Logout)
		r.Post(sdk.RouteV1Refresh, authHandler.RefreshToken)

		r.Post(sdk.RouteV1ForgotPassword, passwordResetHandler.ForgotPassword)
		r.Post(sdk.RouteV1ResetPassword, passwordResetHandler.ResetPassword)

		r.Post(sdk.RouteV1OAuthLogin, oidcAuthHandler.Login)
		r.Post(sdk.RouteV1SSOLogin, oidcAuthHandler.SSOLogin)
		r.Get(sdk.RouteV1OAuthCallback, oidcAuthHandler.Callback)

		r.Post(sdk.RouteV1TOTPLogin, mfaHandler.Login)
	})

	// OIDC provider management
	r.With(require(sdk.ScopeOIDCCreate)).Post(sdk.RouteV1OAuthProviders, oidcProvidersHandler.CreateOIDCProvider)
	r.With(require(sdk.ScopeOIDCRead)).Get(sdk.RouteV1OAuthProviders, oidcProvidersHandler.ListOIDCProviders)
	r.With(require(sdk.ScopeOIDCRead)).Get(sdk.RouteV1OAuthProvider, oidcProvidersHandler.GetOIDCProvider)
	r.With(require(sdk.ScopeOIDCUpdate)).Put(sdk.RouteV1OAuthProvider, oidcProvidersHandler.UpdateOIDCProvider)
	r.With(require(sdk.ScopeOIDCDelete)).Delete(sdk.RouteV1OAuthProvider, oidcProvidersHandler.DeleteOIDCProvider)

	// RBAC - Permissions
	r.With(require(sdk.ScopeRoleRead)).Get(sdk.RouteV1Permissions, rbacHandler.ListPermissions)

	// RBAC - Roles
	r.With(require(sdk.ScopeRoleCreate)).Post(sdk.RouteV1Roles, rbacHandler.CreateRole)
	r.With(require(sdk.ScopeRoleRead)).Get(sdk.RouteV1Roles, rbacHandler.ListRoles)
	r.With(require(sdk.ScopeRoleRead)).Get(sdk.RouteV1Role, rbacHandler.GetRole)
	r.With(require(sdk.ScopeRoleUpdate)).Put(sdk.RouteV1Role, rbacHandler.UpdateRole)
	r.With(require(sdk.ScopeRoleDelete)).Delete(sdk.RouteV1Role, rbacHandler.DeleteRole)

	// RBAC - Role permissions
	r.With(require(sdk.ScopeRoleRead)).Get(sdk.RouteV1RolePermissions, rbacHandler.GetRolePermissions)
	r.With(require(sdk.ScopeRoleUpdate)).Put(sdk.RouteV1RolePermissions, rbacHandler.SetRolePermissions)

	// RBAC - User roles
	r.With(require(sdk.ScopeUserRead)).Get(sdk.RouteV1UserRoles, rbacHandler.GetUserRoles)
	r.With(require(sdk.ScopeUserAssign)).Put(sdk.RouteV1UserRoles, rbacHandler.SetUserRoles)

	// RBAC - User direct permissions
	r.With(require(sdk.ScopeUserRead)).Get(sdk.RouteV1UserPermissions, rbacHandler.GetDirectPermissions)
	r.With(require(sdk.ScopeUserAssign)).Put(sdk.RouteV1UserPermissions, rbacHandler.SetDirectPermissions)

	// TOTP MFA management endpoints
	r.With(jwtMiddleware.Authenticate()).Post(sdk.RouteV1TOTPSetup, mfaHandler.Setup)
	r.With(jwtMiddleware.Authenticate()).Post(sdk.RouteV1TOTPEnable, mfaHandler.Enable)
	r.With(jwtMiddleware.Authenticate()).Delete(sdk.RouteV1TOTPDisable, mfaHandler.Disable)
	r.With(jwtMiddleware.Authenticate()).Get(sdk.RouteV1TOTPStatus, mfaHandler.Status)
	r.With(jwtMiddleware.Authenticate()).Post(sdk.RouteV1TOTPRegenerateCodes, mfaHandler.RegenerateCodes)

	return &Server{
		&http.Server{
			Addr:              config.Address,
			Handler:           r,
			ReadHeaderTimeout: 5 * time.Second, // Prevents Slowloris attacks
		},
	}
}
