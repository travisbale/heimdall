package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
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
	"github.com/travisbale/heimdall/sdk"
)

const (
	// Argon2 parameters (OWASP recommended for password hashing)
	argon2Iterations = 2         // Number of iterations
	argon2Memory     = 64 * 1024 // Memory in KiB (64 MB)
	argon2Threads    = 4         // Number of threads
	argon2KeyLength  = 32        // Length of the generated key in bytes
	saltLength       = 16        // Length of the salt in bytes
)

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
	TrustedProxyMode   bool // Enable IP extraction from X-Forwarded-For when behind reverse proxy
	CORSAllowedOrigins []string
}

// Server wraps the HTTP and gRPC servers and their dependencies
type Server struct {
	httpServer   *http.Server
	grpcServer   *grpc.Server
	db           *postgres.DB
	emailService interface{ Close() }
	logger       *slog.Logger
}

// NewServer creates a new server instance with all dependencies
func NewServer(ctx context.Context, config *Config) (*Server, error) {
	logger := slog.Default()

	db, err := postgres.NewDB(ctx, config.DatabaseURL, logger.With("module", "postgres"))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run migrations on startup to ensure schema is current
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

	passwordHasher := argon2.NewHasher(&argon2.Config{
		Memory:      argon2Memory,
		Iterations:  argon2Iterations,
		SaltLength:  saltLength,
		KeyLength:   argon2KeyLength,
		Parallelism: argon2Threads,
	})

	emailService, err := mailman.NewEmailService(config.MailmanGRPCAddress, config.PublicURL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create email service: %w", err)
	}

	// AES cipher encrypts client secrets for OIDC providers stored in database
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

	usersDB := postgres.NewUsersDB(db)
	verificationTokensDB := postgres.NewVerificationTokensDB(db)
	passwordResetTokensDB := postgres.NewPasswordResetTokensDB(db)
	loginAttemptsDB := postgres.NewLoginAttemptsDB(db)
	oidcProvidersDB := postgres.NewOIDCProvidersDB(db, cipher)
	oidcLinksDB := postgres.NewOIDCLinksDB(db)
	oidcSessionsDB := postgres.NewOIDCSessionsDB(db)

	loginAttemptsService := auth.NewLoginAttemptsService(loginAttemptsDB, logger.With("module", "login_attempts_service"))

	// System-wide providers enable "Login with Google/GitHub" before user authentication
	// Tenant-specific providers (stored in DB) are used for enterprise SSO
	systemProviders := make(map[sdk.OIDCProviderType]auth.OIDCProvider)

	oidcService := auth.NewOIDCService(&auth.OIDCServiceConfig{
		OIDCProviderDB:     oidcProvidersDB,
		OIDCLinkDB:         oidcLinksDB,
		OIDCSessionDB:      oidcSessionsDB,
		UserDB:             usersDB,
		SystemProviders:    systemProviders,
		RegistrationClient: oidc.NewRegistrationClient(),
		ProviderFactory:    oidc.NewProviderFactory(),
		PublicURL:          config.PublicURL,
		Logger:             logger.With("module", "oidc_service"),
	})

	authService := auth.NewUserService(&auth.UserServiceConfig{
		UserDB:               usersDB,
		Hasher:               passwordHasher,
		EmailService:         emailService,
		VerificationTokenDB:  verificationTokensDB,
		PasswordResetTokenDB: passwordResetTokensDB,
		LoginAttemptsService: loginAttemptsService,
		OIDCService:          oidcService,
		Logger:               logger.With("module", "user_service"),
	})

	httpServer := http.NewServer(&http.Config{
		Address:            config.HTTPAddress,
		UserService:        authService,
		OIDCService:        oidcService,
		JWTService:         jwtService,
		Environment:        config.Environment,
		TrustedProxyMode:   config.TrustedProxyMode,
		CORSAllowedOrigins: config.CORSAllowedOrigins,
		Logger:             logger.With("module", "http_server"),
	})

	grpcServer := grpc.NewServer(&grpc.Config{
		Addr:        config.GRPCAddress,
		AuthService: authService,
		Logger:      logger.With("module", "grpc_server"),
	})

	return &Server{
		httpServer:   httpServer,
		grpcServer:   grpcServer,
		db:           db,
		emailService: emailService,
		logger:       logger,
	}, nil
}

// Start begins listening for HTTP and gRPC requests
func (s *Server) Start() error {
	// Run gRPC in background, HTTP blocks main thread for simple shutdown handling
	go func() {
		if err := s.grpcServer.ListenAndServe(); err != nil {
			s.logger.Error("gRPC server error", "error", err)
		}
	}()

	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.grpcServer.GracefulStop()
	s.emailService.Close()
	s.db.Close()

	return s.httpServer.Shutdown(ctx)
}
