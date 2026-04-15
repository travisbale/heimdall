package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/travisbale/heimdall/internal/api/grpc"
	"github.com/travisbale/heimdall/internal/api/rest"
	"github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/travisbale/heimdall/internal/email/console"
	"github.com/travisbale/heimdall/internal/email/mailman"
	"github.com/travisbale/heimdall/internal/email/webhook"
)

// Server wraps the HTTP and gRPC servers and their dependencies
type Server struct {
	httpServer  *http.Server
	grpcServer  *grpc.Server
	db          *postgres.DB
	emailClient interface{ Close() }
}

// NewServer creates a new server instance with all dependencies
func NewServer(ctx context.Context, config *Config) (*Server, error) {
	// Setup database connection and run migrations
	db, err := setupDatabase(ctx, config.DatabaseURL)
	if err != nil {
		return nil, err
	}

	// Setup email client based on configuration
	emailClient, err := newEmailClient(config)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create email service: %w", err)
	}

	// Setup encryption cipher for OIDC client secrets
	cipher, err := setupEncryption(config.EncryptionKey)
	if err != nil {
		db.Close()
		emailClient.Close()
		return nil, err
	}

	// Initialize database access layer
	dbs := initializeDatabases(db, cipher)

	// Initialize OAuth/OIDC providers for individual logins
	systemProviders, err := initializeSystemProviders(ctx, config)
	if err != nil {
		db.Close()
		emailClient.Close()
		return nil, err
	}

	logger := slog.Default()

	// Initialize business logic services
	services, err := initializeServices(config, dbs, systemProviders, emailClient, cipher, logger)
	if err != nil {
		db.Close()
		emailClient.Close()
		return nil, fmt.Errorf("failed to initialize services: %w", err)
	}

	// Create HTTP router and server
	router := &rest.Router{
		DB:                  db,
		AuthService:         services.auth,
		UserService:         services.user,
		PasswordService:     services.password,
		MFAService:          services.mfa,
		OIDCAuthService:     services.oidcAuth,
		OIDCProviderService: services.oidcProvider,
		RBACService:         services.rbac,
		SessionService:      services.session,
		JWTValidator:        services.jwt,
		SecureCookies:       config.Environment != "development" && config.Environment != "test",
		Environment:         config.Environment,
		TrustedProxyMode:    config.TrustedProxyMode,
		CORSAllowedOrigins:  config.CORSAllowedOrigins,
		Logger:              logger,
	}

	httpServer := &http.Server{
		Addr:              config.HTTPAddress,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Create gRPC server
	grpcServer := grpc.NewServer(&grpc.Config{
		Addr:        config.GRPCAddress,
		AuthService: services.user,
		Logger:      logger,
	})

	return &Server{
		httpServer:  httpServer,
		grpcServer:  grpcServer,
		db:          db,
		emailClient: emailClient,
	}, nil
}

// Start begins listening for HTTP and gRPC requests
func (s *Server) Start() error {
	// Run gRPC in background, HTTP blocks main thread for simple shutdown handling
	go func() {
		// Error already logged by grpcServer
		_ = s.grpcServer.ListenAndServe()
	}()

	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.grpcServer.GracefulStop()
	s.emailClient.Close()
	s.db.Close()

	return s.httpServer.Shutdown(ctx)
}

func newEmailClient(config *Config) (emailClient, error) {
	switch {
	case config.EmailWebhookURL != "":
		return webhook.NewClient(config.EmailWebhookURL, config.PublicURL), nil
	case config.MailmanGRPCAddress != "":
		return mailman.NewClient(config.MailmanGRPCAddress, config.PublicURL)
	default:
		return console.NewClient(slog.Default(), config.PublicURL), nil
	}
}
