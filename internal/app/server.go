package app

import (
	"context"
	"fmt"
	"time"

	"github.com/travisbale/heimdall/hash/argon2"
	"github.com/travisbale/heimdall/internal/api/grpc"
	"github.com/travisbale/heimdall/internal/api/http"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/travisbale/heimdall/internal/email/mailman"
	"github.com/travisbale/heimdall/jwt"
	mailmansdk "github.com/travisbale/mailman/sdk"
)

const (
	// Argon2 parameters (OWASP recommended for password hashing)
	argon2Iterations = 2         // Number of iterations
	argon2Memory     = 64 * 1024 // Memory in KiB (64 MB)
	argon2Threads    = 4         // Number of threads
	argon2KeyLength  = 32        // Length of the generated key in bytes
	saltLength       = 16        // Length of the salt in bytes
)

type logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

// Config holds the configuration for creating a new server
type Config struct {
	HTTPAddress        string
	GRPCAddress        string
	DatabaseURL        string
	JWTPrivateKeyPath  string
	JWTPublicKeyPath   string
	JWTExpiration      time.Duration
	BaseURL            string
	MailmanAddress     string
	Environment        string
	CORSAllowedOrigins []string
	Logger             logger
}

// Server wraps the HTTP and gRPC servers and their dependencies
type Server struct {
	httpServer    *http.Server
	grpcServer    *grpc.Server
	db            *postgres.DB
	mailmanClient *mailmansdk.GRPCClient
}

// NewServer creates a new server instance with all dependencies
func NewServer(ctx context.Context, config *Config) (*Server, error) {
	// Connect to database
	db, err := postgres.NewDB(ctx, config.DatabaseURL, config.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run database migrations
	if err := postgres.MigrateUp(config.DatabaseURL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run database migrations: %w", err)
	}

	// Create JWT issuer
	jwtIssuer, err := jwt.NewIssuer("heimdall", config.JWTPrivateKeyPath, config.JWTExpiration)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create JWT issuer: %w", err)
	}

	// Create JWT validator
	jwtValidator, err := jwt.NewValidator(config.JWTPublicKeyPath)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create JWT validator: %w", err)
	}

	jwtService := &jwt.Service{
		Issuer:    jwtIssuer,
		Validator: jwtValidator,
	}

	// Create password hasher
	passwordHasher := argon2.NewArgon2Hasher(argon2Memory, argon2Iterations, saltLength, argon2KeyLength, argon2Threads)

	// Create mailman gRPC client
	mailmanClient, err := mailmansdk.NewGRPCClient(config.MailmanAddress)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to mailman: %w", err)
	}

	// Create email service using mailman
	emailService := mailman.NewEmailService(mailmanClient, config.BaseURL)

	// Create database layer
	usersDB := postgres.NewUsersDB(db)
	verificationTokensDB := postgres.NewVerificationTokensDB(db)
	passwordResetTokensDB := postgres.NewPasswordResetTokensDB(db)

	// Create auth service
	authService := auth.NewUserService(&auth.UserServiceConfig{
		UserDB:               usersDB,
		Hasher:               passwordHasher,
		EmailService:         emailService,
		VerificationTokenDB:  verificationTokensDB,
		PasswordResetTokenDB: passwordResetTokensDB,
		Logger:               config.Logger,
	})

	httpServer := http.NewServer(&http.Config{
		Address:              config.HTTPAddress,
		UserService:          authService,
		RegistrationService:  authService,
		PasswordResetService: authService,
		JWTService:           jwtService,
		Environment:          config.Environment,
		RefreshExpiration:    config.JWTExpiration, // Used for refresh token cookie max-age
		CORSAllowedOrigins:   config.CORSAllowedOrigins,
	})

	// Create gRPC server
	grpcServer := grpc.NewServer(config.GRPCAddress, authService)

	return &Server{
		httpServer:    httpServer,
		grpcServer:    grpcServer,
		db:            db,
		mailmanClient: mailmanClient,
	}, nil
}

// Start begins listening for HTTP and gRPC requests
func (s *Server) Start() error {
	go func() {
		// Start gRPC server in a goroutiner
		if err := s.grpcServer.ListenAndServe(); err != nil {
			fmt.Printf("%v\n", err)
		}
	}()

	// Start HTTP server (blocking)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	// Stop gRPC server
	s.grpcServer.GracefulStop()

	// Close mailman client connection
	if err := s.mailmanClient.Close(); err != nil {
		fmt.Printf("Warning: failed to close mailman client: %v\n", err)
	}

	// Close database connection
	s.db.Close()

	// Shutdown HTTP server
	return s.httpServer.Shutdown(ctx)
}
