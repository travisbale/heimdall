package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/jwt"
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
	registrationHandler := NewRegistrationHandler(config.RegistrationService)
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
	router.Get("/healthz", HandleHealth)

	// API v1 routes
	router.Route("/v1", func(router chi.Router) {
		// Registration endpoints (public)
		router.Post("/register", registrationHandler.Register)
		router.Get("/verify-email", registrationHandler.ConfirmRegistration)

		// Authentication endpoints (public)
		router.Post("/login", authHandler.Login)
		router.Post("/logout", authHandler.Logout)
		router.Post("/refresh", authHandler.RefreshToken)

		// Password reset endpoints (public)
		router.Post("/forgot-password", passwordResetHandler.ForgotPassword)
		router.Post("/reset-password", passwordResetHandler.ResetPassword)
	})

	return &Server{
		&http.Server{
			Addr:              config.Address,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}
