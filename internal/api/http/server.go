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
	h := initializeHandlers(config)

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

	registerRoutes(r, h, auth, require, config.Environment)

	return &Server{
		&http.Server{
			Addr:              config.Address,
			Handler:           r,
			ReadHeaderTimeout: 5 * time.Second, // Prevents Slowloris attacks
		},
	}
}

// handlers holds all HTTP request handlers
type handlers struct {
	health        *HealthHandler
	auth          *AuthHandler
	registration  *RegistrationHandler
	passwordReset *PasswordResetHandler
	oidcAuth      *OIDCAuthHandler
	oidcProviders *OIDCProvidersHandler
	rbac          *RBACHandler
	mfa           *MFAHandler
	sessions      *SessionsHandler
}

// initializeHandlers creates all HTTP handlers with their dependencies
func initializeHandlers(config *Config) *handlers {
	secureCookies := config.SecureCookies()

	return &handlers{
		health: &HealthHandler{
			DB: config.Database,
		},
		auth: &AuthHandler{
			AuthService:   config.AuthService,
			SecureCookies: secureCookies,
		},
		registration: &RegistrationHandler{
			UserService:   config.UserService,
			AuthService:   config.AuthService,
			SecureCookies: secureCookies,
		},
		passwordReset: &PasswordResetHandler{
			PasswordService: config.PasswordService,
		},
		oidcAuth: &OIDCAuthHandler{
			OIDCAuthService: config.OIDCAuthService,
			AuthService:     config.AuthService,
			SecureCookies:   secureCookies,
		},
		oidcProviders: &OIDCProvidersHandler{
			OIDCProviderService: config.OIDCProviderService,
		},
		rbac: &RBACHandler{
			RBACService: config.RBACService,
		},
		mfa: &MFAHandler{
			MFAService:    config.MFAService,
			AuthService:   config.AuthService,
			SecureCookies: secureCookies,
			Logger:        config.Logger,
		},
		sessions: &SessionsHandler{
			SessionService: config.SessionService,
			AuthService:    config.AuthService,
			SecureCookies:  secureCookies,
		},
	}
}

// registerRoutes configures all HTTP routes with their handlers and middleware
func registerRoutes(r chi.Router, h *handlers, auth func(http.Handler) http.Handler, require func(scopes ...jwt.Scope) func(http.Handler) http.Handler, environment string) {
	// Health check endpoint (nginx internal, no auth required, no rate limit)
	r.Head(sdk.RouteHealth, h.health.HandleHealth)

	// Supported OAuth provider types (public, no auth required, no rate limit)
	r.Get(sdk.RouteV1OAuthSupportedTypes, ListSupportedProviders)

	// Moderate rate limit for registration endpoints (less sensitive than authentication)
	r.Group(func(r chi.Router) {
		if environment != "test" {
			r.Use(newRateLimitMiddleware(ModerateRateLimit))
		}

		r.Post(sdk.RouteV1Register, h.registration.Register)
		r.Post(sdk.RouteV1VerifyEmail, h.registration.ConfirmRegistration)
	})

	// Strict rate limit for authentication endpoints (prevent brute force attacks)
	r.Group(func(r chi.Router) {
		if environment != "test" {
			r.Use(newRateLimitMiddleware(StrictRateLimit))
		}

		r.Post(sdk.RouteV1Login, h.auth.Login)
		r.Post(sdk.RouteV1Refresh, h.auth.RefreshToken)
		r.Delete(sdk.RouteV1Refresh, h.auth.Logout)

		r.Post(sdk.RouteV1ForgotPassword, h.passwordReset.ForgotPassword)
		r.Post(sdk.RouteV1ResetPassword, h.passwordReset.ResetPassword)

		r.Post(sdk.RouteV1OAuthLogin, h.oidcAuth.Login)
		r.Post(sdk.RouteV1SSOLogin, h.oidcAuth.SSOLogin)
		r.Get(sdk.RouteV1OAuthCallback, h.oidcAuth.Callback)

		r.Post(sdk.RouteV1MFAVerify, h.mfa.Login)

		// Required MFA setup (unauthenticated, uses setup token from login response)
		r.Post(sdk.RouteV1MFARequiredSetup, h.mfa.RequiredSetup)
		r.Post(sdk.RouteV1MFARequiredEnable, h.mfa.RequiredEnable)
	})

	// OIDC provider management
	r.With(require(iam.ScopeOIDCCreate)).Post(sdk.RouteV1OAuthProviders, h.oidcProviders.CreateOIDCProvider)
	r.With(require(iam.ScopeOIDCRead)).Get(sdk.RouteV1OAuthProviders, h.oidcProviders.ListOIDCProviders)
	r.With(require(iam.ScopeOIDCRead)).Get(sdk.RouteV1OAuthProvider, h.oidcProviders.GetOIDCProvider)
	r.With(require(iam.ScopeOIDCUpdate)).Put(sdk.RouteV1OAuthProvider, h.oidcProviders.UpdateOIDCProvider)
	r.With(require(iam.ScopeOIDCDelete)).Delete(sdk.RouteV1OAuthProvider, h.oidcProviders.DeleteOIDCProvider)

	// RBAC - Permissions
	r.With(require(iam.ScopeRoleRead)).Get(sdk.RouteV1Permissions, h.rbac.ListPermissions)

	// RBAC - Roles
	r.With(require(iam.ScopeRoleCreate)).Post(sdk.RouteV1Roles, h.rbac.CreateRole)
	r.With(require(iam.ScopeRoleRead)).Get(sdk.RouteV1Roles, h.rbac.ListRoles)
	r.With(require(iam.ScopeRoleRead)).Get(sdk.RouteV1Role, h.rbac.GetRole)
	r.With(require(iam.ScopeRoleUpdate)).Put(sdk.RouteV1Role, h.rbac.UpdateRole)
	r.With(require(iam.ScopeRoleDelete)).Delete(sdk.RouteV1Role, h.rbac.DeleteRole)

	// RBAC - Role permissions
	r.With(require(iam.ScopeRoleRead)).Get(sdk.RouteV1RolePermissions, h.rbac.GetRolePermissions)
	r.With(require(iam.ScopeRoleUpdate)).Put(sdk.RouteV1RolePermissions, h.rbac.SetRolePermissions)

	// RBAC - User roles
	r.With(require(iam.ScopeUserRead)).Get(sdk.RouteV1UserRoles, h.rbac.GetUserRoles)
	r.With(require(iam.ScopeUserAssign)).Put(sdk.RouteV1UserRoles, h.rbac.SetUserRoles)

	// RBAC - User direct permissions
	r.With(require(iam.ScopeUserRead)).Get(sdk.RouteV1UserPermissions, h.rbac.GetDirectPermissions)
	r.With(require(iam.ScopeUserAssign)).Put(sdk.RouteV1UserPermissions, h.rbac.SetDirectPermissions)

	// MFA management endpoints
	r.With(auth).Post(sdk.RouteV1MFASetup, h.mfa.Setup)
	r.With(auth).Post(sdk.RouteV1MFAEnable, h.mfa.Enable)
	r.With(auth).Delete(sdk.RouteV1MFADisable, h.mfa.Disable)
	r.With(auth).Get(sdk.RouteV1MFAStatus, h.mfa.Status)
	r.With(auth).Post(sdk.RouteV1MFARegenerateCodes, h.mfa.RegenerateCodes)

	// Session management endpoints
	r.With(auth).Get(sdk.RouteV1Sessions, h.sessions.ListSessions)
	r.With(auth).Delete(sdk.RouteV1Sessions, h.sessions.RevokeAllSessions)
	r.With(auth).Delete(sdk.RouteV1SessionByID, h.sessions.RevokeSession)
}
