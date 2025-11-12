package http

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

type oidcService interface {
	StartOIDCLogin(ctx context.Context, providerType sdk.OIDCProviderType) (string, error)
	StartSSOLogin(ctx context.Context, domain string) (string, error)
	HandleOIDCCallback(ctx context.Context, state, code string) (*auth.User, *auth.OIDCLink, error)
	// Admin operations
	CreateOIDCProvider(ctx context.Context, provider *auth.OIDCProviderConfig, accessToken string) (*auth.OIDCProviderConfig, error)
	GetOIDCProvider(ctx context.Context, providerID uuid.UUID) (*auth.OIDCProviderConfig, error)
	ListOIDCProviders(ctx context.Context) ([]*auth.OIDCProviderConfig, error)
	UpdateOIDCProvider(ctx context.Context, params *auth.UpdateOIDCProviderParams) (*auth.OIDCProviderConfig, error)
	DeleteOIDCProvider(ctx context.Context, providerID uuid.UUID) error
}

type Config struct {
	Address              string
	UserService          userService
	RegistrationService  registrationService
	PasswordResetService passwordResetService
	OIDCService          oidcService
	JWTService           jwtService
	Environment          string   // "development", "staging", "production"
	CORSAllowedOrigins   []string // Allowed origins for CORS (e.g., ["http://localhost:5173"])
}

type jwtService interface {
	IssueAccessToken(userID, tenantID uuid.UUID, scopes []string) (string, error)
	IssueRefreshToken(userID, tenantID uuid.UUID) (string, error)
	ValidateToken(token string) (*jwt.Claims, error)
	GetRefreshTokenExpiration() time.Duration
}

type Server struct {
	*http.Server
}

func NewServer(config *Config) *Server {
	// Determine if we should use secure cookies (HTTPS only)
	secureCookies := config.Environment == "production" || config.Environment == "staging"

	// Create domain handlers
	authHandler := NewAuthHandler(config.UserService, config.JWTService, secureCookies)
	registrationHandler := NewRegistrationHandler(config.RegistrationService, config.UserService, config.JWTService, secureCookies)
	passwordResetHandler := NewPasswordResetHandler(config.PasswordResetService)
	oidcAuthHandler := NewOIDCAuthHandler(config.OIDCService, config.UserService, config.JWTService, secureCookies)
	oidcProvidersHandler := NewOIDCProvidersHandler(config.OIDCService)

	router := chi.NewRouter()

	// Global middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)

	// CORS configuration (only if origins are specified)
	if len(config.CORSAllowedOrigins) > 0 {
		router.Use(cors.Handler(cors.Options{
			AllowedOrigins:   config.CORSAllowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: true,
			MaxAge:           300, // Maximum value not ignored by any major browsers
		}))
	}

	// Health check endpoint (public, no auth required)
	router.Head(sdk.RouteHealth, HandleHealth)

	// Registration endpoints (public)
	router.Post(sdk.RouteV1Register, registrationHandler.Register)
	router.Post(sdk.RouteV1VerifyEmail, registrationHandler.ConfirmRegistration)
	router.Post(sdk.RouteV1ResendVerification, registrationHandler.ResendVerificationEmail)

	// Authentication endpoints (public)
	router.Post(sdk.RouteV1Login, authHandler.Login)
	router.Post(sdk.RouteV1Logout, authHandler.Logout)
	router.Post(sdk.RouteV1Refresh, authHandler.RefreshToken)

	// Password reset endpoints (public)
	router.Post(sdk.RouteV1ForgotPassword, passwordResetHandler.ForgotPassword)
	router.Post(sdk.RouteV1ResetPassword, passwordResetHandler.ResetPassword)

	// OAuth/SSO endpoints (public)
	router.Post(sdk.RouteV1OAuthLogin, oidcAuthHandler.Login)      // Start individual OAuth login flow
	router.Post(sdk.RouteV1SSOLogin, oidcAuthHandler.SSOLogin)     // Start corporate SSO login flow
	router.Get(sdk.RouteV1OAuthCallback, oidcAuthHandler.Callback) // Handle OAuth callback (public)

	// Protected routes (require JWT authentication)
	router.Group(func(protected chi.Router) {
		protected.Use(jwt.Middleware(config.JWTService))

		// OIDC provider management endpoints (authenticated)
		protected.Post(sdk.RouteV1OAuthProviders, oidcProvidersHandler.CreateProvider)  // Create OIDC provider
		protected.Get(sdk.RouteV1OAuthProviders, oidcProvidersHandler.ListProviders)    // List OIDC providers
		protected.Get(sdk.RouteV1OAuthProvider, oidcProvidersHandler.GetProvider)       // Get OIDC provider by type
		protected.Put(sdk.RouteV1OAuthProvider, oidcProvidersHandler.UpdateProvider)    // Update OIDC provider
		protected.Delete(sdk.RouteV1OAuthProvider, oidcProvidersHandler.DeleteProvider) // Delete OIDC provider
	})

	return &Server{
		&http.Server{
			Addr:              config.Address,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}
