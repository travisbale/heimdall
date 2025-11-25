package app

import (
	"context"
	"fmt"

	"github.com/travisbale/heimdall/clog"
	"github.com/travisbale/heimdall/internal/api/grpc"
	"github.com/travisbale/heimdall/internal/api/http"
	"github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/travisbale/heimdall/internal/email/mailman"
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

	// Setup email client
	emailClient, err := mailman.NewClient(config.MailmanGRPCAddress, config.PublicURL)
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

	// Initialize business logic services
	services, err := initializeServices(config, dbs, systemProviders, emailClient, cipher)
	if err != nil {
		db.Close()
		emailClient.Close()
		return nil, fmt.Errorf("failed to initialize services: %w", err)
	}

	// Create HTTP server
	httpServer := http.NewServer(&http.Config{
		Address:            config.HTTPAddress,
		Database:           db,
		UserService:        services.user,
		PasswordService:    services.password,
		MFAService:         services.mfa,
		OIDCService:        services.oidc,
		RBACService:        services.rbac,
		AuthService:        services.auth,
		JWTValidator:       services.jwt,
		Environment:        config.Environment,
		TrustedProxyMode:   config.TrustedProxyMode,
		CORSAllowedOrigins: config.CORSAllowedOrigins,
		Logger:             clog.New("http"),
	})

	// Create gRPC server
	grpcServer := grpc.NewServer(&grpc.Config{
		Addr:        config.GRPCAddress,
		AuthService: services.user,
		Logger:      clog.New("grpc_server"),
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
