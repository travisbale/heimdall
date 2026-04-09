//go:build integration

package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/travisbale/heimdall/internal/app"
	heimdalldb "github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/jwt"
)

// Harness holds all shared state for integration tests
type Harness struct {
	BaseURL     string
	DB          *pgxpool.Pool
	Validator   *jwt.Validator
	OIDCMockURL string // Base URL of the mock OIDC server (e.g. http://localhost:12345)
}

var harness *Harness

// NewClient creates an unauthenticated SDK client pointed at the test server
func (h *Harness) NewClient(t *testing.T, opts ...sdk.Option) *sdk.HTTPClient {
	t.Helper()
	client, err := sdk.NewHTTPClient(h.BaseURL, opts...)
	if err != nil {
		t.Fatalf("failed to create SDK client: %v", err)
	}
	return client
}

// setup initializes the test infrastructure: postgres container, RSA keys, and heimdall server
func setup(ctx context.Context) (h *Harness, cleanup func(), err error) {
	var (
		pgContainer   *postgres.PostgresContainer
		oidcContainer testcontainers.Container
		pool          *pgxpool.Pool
		tmpDir        string
		server        *app.Server
	)

	// If setup fails partway through, clean up everything allocated so far
	defer func() {
		if err != nil {
			if server != nil {
				_ = server.Shutdown(ctx)
			}
			if tmpDir != "" {
				os.RemoveAll(tmpDir)
			}
			if pool != nil {
				pool.Close()
			}
			if oidcContainer != nil {
				_ = oidcContainer.Terminate(ctx)
			}
			if pgContainer != nil {
				_ = pgContainer.Terminate(ctx)
			}
		}
	}()

	var adminURL string
	pgContainer, adminURL, err = startPostgres(ctx)
	if err != nil {
		return nil, nil, err
	}

	dbURL, err := createAppUser(ctx, pgContainer, adminURL)
	if err != nil {
		return nil, nil, err
	}

	// Connect as admin for test queries (bypasses RLS for token extraction)
	pool, err = pgxpool.New(ctx, adminURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	tmpDir, err = os.MkdirTemp("", "heimdall-test-keys-*")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	privateKeyPath, publicKeyPath, err := generateRSAKeys(tmpDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA keys: %w", err)
	}

	validator, err := jwt.NewValidator(publicKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create JWT validator: %w", err)
	}

	encryptionKey := make([]byte, 32)
	if _, err = rand.Read(encryptionKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	var oidcMockURL string
	oidcContainer, oidcMockURL, err = startOIDCMock(ctx)
	if err != nil {
		return nil, nil, err
	}

	server, err = app.NewServer(ctx, &app.Config{
		DatabaseURL:       dbURL,
		HTTPAddress:       ":8080",
		GRPCAddress:       ":9090",
		JWTIssuer:         "heimdall",
		JWTPrivateKeyPath: privateKeyPath,
		JWTPublicKeyPath:  publicKeyPath,
		JWTExpiration:     24 * time.Hour,
		PublicURL:         "http://localhost:8080",
		Environment:       "test",
		EncryptionKey:     hex.EncodeToString(encryptionKey),
		TOTPPeriod:        3,

		// System OAuth providers pointed at mock OIDC server
		GoogleClientID:     "mock-google-client-id",
		GoogleClientSecret: "mock-google-client-secret",
		GoogleIssuerURL:    oidcMockURL + "/google",

		MicrosoftClientID:     "mock-microsoft-client-id",
		MicrosoftClientSecret: "mock-microsoft-client-secret",
		MicrosoftIssuerURL:    oidcMockURL + "/microsoft",

		GitHubClientID:     "mock-github-client-id",
		GitHubClientSecret: "mock-github-client-secret",
		GitHubAuthURL:      oidcMockURL + "/github/authorize",
		GitHubTokenURL:     oidcMockURL + "/github/token",
		GitHubAPIBase:      oidcMockURL + "/github/api",
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create server: %w", err)
	}

	go func() { _ = server.Start() }()

	if err = waitForReady("localhost:8080", 5*time.Second); err != nil {
		return nil, nil, fmt.Errorf("server failed to start: %w", err)
	}

	h = &Harness{
		BaseURL:     "http://localhost:8080",
		DB:          pool,
		Validator:   validator,
		OIDCMockURL: oidcMockURL,
	}

	cleanup = func() {
		_ = server.Shutdown(ctx)
		os.RemoveAll(tmpDir)
		pool.Close()
		_ = oidcContainer.Terminate(ctx)
		_ = pgContainer.Terminate(ctx)
	}

	return h, cleanup, nil
}

func startPostgres(ctx context.Context) (*postgres.PostgresContainer, string, error) {
	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("heimdall_test"),
		postgres.WithUsername("admin"),
		postgres.WithPassword("admin_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to start postgres container: %w", err)
	}

	adminURL, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, "", fmt.Errorf("failed to get connection string: %w", err)
	}

	if err = heimdalldb.MigrateUp(adminURL); err != nil {
		_ = container.Terminate(ctx)
		return nil, "", fmt.Errorf("failed to run migrations: %w", err)
	}

	return container, adminURL, nil
}

// createAppUser creates a non-superuser for the application and returns its connection URL.
// Superusers bypass RLS, so the app must connect as a regular user for tenant isolation to work.
func createAppUser(ctx context.Context, container testcontainers.Container, adminURL string) (string, error) {
	pool, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		return "", fmt.Errorf("failed to connect as admin: %w", err)
	}
	defer pool.Close()

	_, err = pool.Exec(ctx, `
		CREATE USER heimdall WITH PASSWORD 'test_password';
		GRANT CONNECT ON DATABASE heimdall_test TO heimdall;
		GRANT USAGE ON SCHEMA public TO heimdall;
		GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO heimdall;
		GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO heimdall;
	`)
	if err != nil {
		return "", fmt.Errorf("failed to create application user: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get container host: %w", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		return "", fmt.Errorf("failed to get container port: %w", err)
	}

	return fmt.Sprintf("postgres://heimdall:test_password@%s:%s/heimdall_test?sslmode=disable", host, port.Port()), nil
}

func startOIDCMock(ctx context.Context) (testcontainers.Container, string, error) {
	configPath, err := filepath.Abs("testdata/oidc-mock-config.json")
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve OIDC mock config path: %w", err)
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "ghcr.io/navikt/mock-oauth2-server:2.1.1",
			ExposedPorts: []string{"8080/tcp"},
			Files: []testcontainers.ContainerFile{
				{
					HostFilePath:      configPath,
					ContainerFilePath: "/config.json",
				},
			},
			Env: map[string]string{
				"JSON_CONFIG_PATH": "/config.json",
			},
			WaitingFor: wait.ForHTTP("/.well-known/openid-configuration").
				WithPort("8080/tcp").
				WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to start OIDC mock container: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, "", fmt.Errorf("failed to get OIDC mock host: %w", err)
	}
	port, err := container.MappedPort(ctx, "8080")
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, "", fmt.Errorf("failed to get OIDC mock port: %w", err)
	}

	mockURL := fmt.Sprintf("http://%s:%s", host, port.Port())
	return container, mockURL, nil
}

func waitForReady(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server at %s not ready after %s", addr, timeout)
}

func generateRSAKeys(dir string) (privateKeyPath, publicKeyPath string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	privateKeyPath = filepath.Join(dir, "private.pem")
	privFile, err := os.Create(privateKeyPath)
	if err != nil {
		return "", "", err
	}
	defer privFile.Close()

	if err = pem.Encode(privFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		return "", "", err
	}

	publicKeyPath = filepath.Join(dir, "public.pem")
	pubFile, err := os.Create(publicKeyPath)
	if err != nil {
		return "", "", err
	}
	defer pubFile.Close()

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}

	if err = pem.Encode(pubFile, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}); err != nil {
		return "", "", err
	}

	return privateKeyPath, publicKeyPath, nil
}
