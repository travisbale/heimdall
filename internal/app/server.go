package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/travisbale/heimdall/crypto/aes"
	"github.com/travisbale/heimdall/crypto/argon2"
	"github.com/travisbale/heimdall/internal/api/grpc"
	"github.com/travisbale/heimdall/internal/api/http"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/travisbale/heimdall/internal/email/mailman"
	"github.com/travisbale/heimdall/internal/oidc"
	"github.com/travisbale/heimdall/jwt"
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
	JWTIssuer          string
	JWTPrivateKeyPath  string
	JWTPublicKeyPath   string
	JWTExpiration      time.Duration
	PublicURL          string
	MailmanGRPCAddress string
	Environment        string
	EncryptionKey      string
	CORSAllowedOrigins []string
	Logger             logger
}

// Server wraps the HTTP and gRPC servers and their dependencies
type Server struct {
	httpServer   *http.Server
	grpcServer   *grpc.Server
	db           *postgres.DB
	emailService interface{ Close() } // Interface for email service with Close method
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

	jwtConfig := &jwt.Config{
		Issuer:                 config.JWTIssuer,
		PrivateKeyPath:         config.JWTPrivateKeyPath,
		PublicKeyPath:          config.JWTPublicKeyPath,
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: config.JWTExpiration,
	}

	jwtService, err := jwt.NewService(jwtConfig)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create JWT service: %w", err)
	}

	// Create password hasher
	passwordHasher := argon2.NewHasher(&argon2.Config{
		Memory:      argon2Memory,
		Iterations:  argon2Iterations,
		SaltLength:  saltLength,
		KeyLength:   argon2KeyLength,
		Parallelism: argon2Threads,
	})

	// Create email service
	emailService, err := mailman.NewEmailService(config.MailmanGRPCAddress, config.PublicURL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create email service: %w", err)
	}

	// Create AES cipher for encrypting sensitive data
	encryptionKeyBytes, err := hex.DecodeString(config.EncryptionKey)
	if err != nil {
		db.Close()
		emailService.Close()
		return nil, fmt.Errorf("failed to decode encryption key (must be 64 hex characters): %w", err)
	}
	cipher, err := aes.NewCipher(encryptionKeyBytes)
	if err != nil {
		db.Close()
		emailService.Close()
		return nil, fmt.Errorf("failed to create encryption cipher: %w", err)
	}

	// Create database layer
	usersDB := postgres.NewUsersDB(db)
	verificationTokensDB := postgres.NewVerificationTokensDB(db)
	passwordResetTokensDB := postgres.NewPasswordResetTokensDB(db)
	loginAttemptsDB := postgres.NewLoginAttemptsDB(db)
	oauthProvidersDB := postgres.NewOIDCProvidersDB(db, cipher)
	oauthLinksDB := postgres.NewOIDCLinksDB(db)
	oauthSessionsDB := postgres.NewOIDCSessionsDB(db)

	// Create login attempts service
	loginAttemptsService := auth.NewLoginAttemptsService(loginAttemptsDB, config.Logger)

	// Create auth service
	authService := auth.NewUserService(&auth.UserServiceConfig{
		UserDB:               usersDB,
		Hasher:               passwordHasher,
		EmailService:         emailService,
		VerificationTokenDB:  verificationTokensDB,
		PasswordResetTokenDB: passwordResetTokensDB,
		LoginAttemptsService: loginAttemptsService,
		Logger:               config.Logger,
	})

	// Initialize system-wide OIDC providers for public login flow
	// These are configured via environment variables and used when there's no tenant context.
	// After login, the system determines the tenant based on email domain or creates a new one.
	systemProviders := make(map[string]auth.OIDCProvider)

	// Example: Configure Google OAuth for public login
	// In production, read from environment variables:
	//
	//   if googleClientID := os.Getenv("GOOGLE_OAUTH_CLIENT_ID"); googleClientID != "" {
	//       googleClientSecret := os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET")
	//       redirectURI := config.BaseURL + "/v1/oauth/callback"
	//       googleProvider, err := oidc.NewGoogleProvider(ctx, googleClientID, googleClientSecret, redirectURI)
	//       if err != nil {
	//           config.Logger.Error("failed to create Google provider", "error", err)
	//       } else {
	//           systemProviders["google"] = googleProvider
	//           config.Logger.Info("registered system Google OAuth provider")
	//       }
	//   }
	//
	// Similarly for other providers:
	//   if msClientID := os.Getenv("MICROSOFT_OAUTH_CLIENT_ID"); msClientID != "" {
	//       // Microsoft requires tenant ID ("common", "organizations", "consumers", or specific tenant)
	//       tenantID := os.Getenv("MICROSOFT_OAUTH_TENANT_ID")
	//       if tenantID == "" {
	//           tenantID = "common" // Default: allow both work/school and personal accounts
	//       }
	//       msClientSecret := os.Getenv("MICROSOFT_OAUTH_CLIENT_SECRET")
	//       redirectURI := config.BaseURL + "/v1/oauth/callback"
	//       msProvider, err := oidc.NewMicrosoftProvider(ctx, msClientID, msClientSecret, redirectURI, tenantID)
	//       if err != nil {
	//           config.Logger.Error("failed to create Microsoft provider", "error", err)
	//       } else {
	//           systemProviders["microsoft"] = msProvider
	//           config.Logger.Info("registered system Microsoft OAuth provider")
	//       }
	//   }
	//
	//   if ghClientID := os.Getenv("GITHUB_OAUTH_CLIENT_ID"); ghClientID != "" {
	//       ghClientSecret := os.Getenv("GITHUB_OAUTH_CLIENT_SECRET")
	//       redirectURI := config.BaseURL + "/v1/oauth/callback"
	//       ghProvider := oidc.NewGitHubProvider(ghClientID, ghClientSecret, redirectURI)
	//       systemProviders["github"] = ghProvider
	//       config.Logger.Info("registered system GitHub OAuth provider")
	//   }
	//
	// For tenant-specific OAuth configurations (Enterprise SSO):
	// - Admins create OIDC provider configs via the API (stored in database)
	// - The provider factory dynamically creates provider instances from DB config
	// - Used for authenticated "link" operations and corporate SSO with allowed domains

	// Create OIDC registration client for discovery and dynamic registration
	oidcClient := oidc.NewRegistrationClient()

	// Create OIDC provider factory
	providerFactory := oidc.NewProviderFactory()

	// Create OIDC service
	oidcService := auth.NewOIDCService(&auth.OIDCServiceConfig{
		OIDCProviderDB:     oauthProvidersDB,
		OIDCLinkDB:         oauthLinksDB,
		OIDCSessionDB:      oauthSessionsDB,
		UserDB:             usersDB,
		SystemProviders:    systemProviders,
		RegistrationClient: oidcClient,
		ProviderFactory:    providerFactory,
		PublicURL:          config.PublicURL,
		Logger:             config.Logger,
	})

	httpServer := http.NewServer(&http.Config{
		Address:              config.HTTPAddress,
		UserService:          authService,
		RegistrationService:  authService,
		PasswordResetService: authService,
		OIDCService:          oidcService,
		JWTService:           jwtService,
		Environment:          config.Environment,
		CORSAllowedOrigins:   config.CORSAllowedOrigins,
	})

	// Create gRPC server
	grpcServer := grpc.NewServer(&grpc.Config{
		Addr:        config.GRPCAddress,
		AuthService: authService,
	})

	return &Server{
		httpServer:   httpServer,
		grpcServer:   grpcServer,
		db:           db,
		emailService: emailService,
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

	// Close email service connection
	s.emailService.Close()

	// Close database connection
	s.db.Close()

	// Shutdown HTTP server
	return s.httpServer.Shutdown(ctx)
}
