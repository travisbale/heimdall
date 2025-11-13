package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

type Config struct {
	Address            string
	UserService        userService
	OIDCService        oidcService
	JWTService         jwtService
	Environment        string
	TrustedProxyMode   bool // Enable when behind trusted reverse proxy (nginx, cloudflare, etc)
	CORSAllowedOrigins []string
	Logger             logger
}

type Server struct {
	*http.Server
}

func NewServer(config *Config) *Server {
	// Secure cookies required for production/staging to enforce HTTPS-only transmission
	secureCookies := config.Environment != "development"

	// Create domain handlers
	authHandler := NewAuthHandler(config.UserService, config.JWTService, secureCookies, config.TrustedProxyMode, config.Logger)
	registrationHandler := NewRegistrationHandler(config.UserService, config.JWTService, secureCookies)
	passwordResetHandler := NewPasswordResetHandler(config.UserService)
	oidcAuthHandler := NewOIDCAuthHandler(config.OIDCService, config.UserService, config.JWTService, secureCookies)
	oidcProvidersHandler := NewOIDCProvidersHandler(config.OIDCService)

	router := chi.NewRouter()

	// Global middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)

	// CORS enabled only when origins specified (browser-based clients require this)
	if len(config.CORSAllowedOrigins) > 0 {
		router.Use(cors.Handler(cors.Options{
			AllowedOrigins:   config.CORSAllowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: true,
			MaxAge:           300, // Maximum value not ignored by major browsers
		}))
	}

	// Health check endpoint (public, no auth required, no rate limit)
	router.Head(sdk.RouteHealth, HandleHealth)

	// Supported OAuth provider types (public, no auth required, no rate limit)
	router.Get(sdk.RouteV1OAuthSupportedTypes, ListSupportedProviders)

	// Moderate rate limit for registration endpoints (less sensitive than authentication)
	router.Group(func(r chi.Router) {
		r.Use(newRateLimitMiddleware(ModerateRateLimit))

		r.Post(sdk.RouteV1Register, registrationHandler.Register)
		r.Post(sdk.RouteV1VerifyEmail, registrationHandler.ConfirmRegistration)
		r.Post(sdk.RouteV1ResendVerification, registrationHandler.ResendVerificationEmail)
	})

	// Strict rate limit for authentication endpoints (prevent brute force attacks)
	router.Group(func(r chi.Router) {
		r.Use(newRateLimitMiddleware(StrictRateLimit))

		r.Post(sdk.RouteV1Login, authHandler.Login)
		r.Post(sdk.RouteV1Logout, authHandler.Logout)
		r.Post(sdk.RouteV1Refresh, authHandler.RefreshToken)
		r.Post(sdk.RouteV1ForgotPassword, passwordResetHandler.ForgotPassword)
		r.Post(sdk.RouteV1ResetPassword, passwordResetHandler.ResetPassword)
		r.Post(sdk.RouteV1OAuthLogin, oidcAuthHandler.Login)
		r.Post(sdk.RouteV1SSOLogin, oidcAuthHandler.SSOLogin)
		r.Get(sdk.RouteV1OAuthCallback, oidcAuthHandler.Callback)
	})

	// Protected routes require JWT authentication and tenant context
	router.Group(func(r chi.Router) {
		r.Use(jwt.Middleware(config.JWTService))

		r.Post(sdk.RouteV1OAuthProviders, oidcProvidersHandler.CreateProvider)
		r.Get(sdk.RouteV1OAuthProviders, oidcProvidersHandler.ListProviders)
		r.Get(sdk.RouteV1OAuthProvider, oidcProvidersHandler.GetProvider)
		r.Put(sdk.RouteV1OAuthProvider, oidcProvidersHandler.UpdateProvider)
		r.Delete(sdk.RouteV1OAuthProvider, oidcProvidersHandler.DeleteProvider)
	})

	return &Server{
		&http.Server{
			Addr:              config.Address,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second, // Prevents Slowloris attacks
		},
	}
}
