package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

type Config struct {
	Address              string
	UserService          userService
	RegistrationService  registrationService
	PasswordResetService passwordResetService
	JWTService           jwtService
	Environment          string        // "development", "staging", "production"
	RefreshExpiration    time.Duration // Used for refresh token cookie max-age
	CORSAllowedOrigins   []string      // Allowed origins for CORS (e.g., ["http://localhost:5173"])
}

type jwtService interface {
	IssueAccessToken(userID, tenantID uuid.UUID, scopes []string) (string, error)
	IssueRefreshToken(userID, tenantID uuid.UUID) (string, error)
	ValidateToken(token string) (*jwt.Claims, error)
}

type Server struct {
	*http.Server
}

func NewServer(config *Config) *Server {
	// Determine if we should use secure cookies (HTTPS only)
	secureCookies := config.Environment == "production" || config.Environment == "staging"

	// Create domain handlers
	authHandler := NewAuthHandler(config.UserService, config.JWTService, secureCookies, config.RefreshExpiration)
	registrationHandler := NewRegistrationHandler(config.RegistrationService, config.UserService, config.JWTService, secureCookies, config.RefreshExpiration)
	passwordResetHandler := NewPasswordResetHandler(config.PasswordResetService)

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

	return &Server{
		&http.Server{
			Addr:              config.Address,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}
