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

// drainer is satisfied by *http.Server.
type drainer interface {
	ListenAndServe() error
	Shutdown(ctx context.Context) error
}

// stopper is satisfied by *grpc.Server.
type stopper interface {
	ListenAndServe() error
	GracefulStop()
}

// closer is satisfied by *postgres.DB and by every email client.
type closer interface {
	Close()
}

// Server wraps the HTTP and gRPC servers and their dependencies. Held as interfaces so
// the shutdown ordering is testable without real infrastructure.
type Server struct {
	httpServer  drainer
	grpcServer  stopper
	db          closer
	emailClient closer
}

// NewServer creates a new server instance with all dependencies
func NewServer(ctx context.Context, config *Config) (*Server, error) {
	db, err := postgres.NewDB(ctx, config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to build the database pool: %w", err)
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
		ProxySecret:         config.ProxySecret,
		CORSAllowedOrigins:  config.CORSAllowedOrigins,
		Logger:              logger,
	}

	httpServer := newHTTPServer(config.HTTPAddress, router.Handler())

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

// Shutdown drains both servers before releasing anything they depend on. The order
// matters: Shutdown and GracefulStop each block until in-flight work returns, and that
// work is still querying and still sending mail. The deferred closes run even if draining
// fails, so a timeout cannot leak the pool.
func (s *Server) Shutdown(ctx context.Context) error {
	defer s.db.Close()
	defer s.emailClient.Close()

	s.grpcServer.GracefulStop()
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

// newHTTPServer bounds how long one connection can occupy the server: without these a
// slow reader or an idle keep-alive holds its slot indefinitely.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
