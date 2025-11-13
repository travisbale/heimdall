package main

import (
	"time"

	"github.com/urfave/cli/v2"
)

// CLI flags shared across commands
var (
	DebugFlag = &cli.BoolFlag{
		Name:        "debug",
		Usage:       "Enable debug-level logging",
		EnvVars:     []string{"DEBUG"},
		Destination: &config.Debug,
	}

	LogFormatFlag = &cli.StringFlag{
		Name:        "log-format",
		Usage:       "Log format: text (human-readable) or json (log aggregation)",
		Value:       "text",
		EnvVars:     []string{"LOG_FORMAT"},
		Destination: &config.LogFormat,
	}

	DatabaseURLFlag = &cli.StringFlag{
		Name:        "database-url",
		Aliases:     []string{"u"},
		Usage:       "PostgreSQL connection URL",
		Value:       "postgres://heimdall:heimdall_dev_password@localhost:5432/heimdall?sslmode=disable",
		EnvVars:     []string{"DATABASE_URL"},
		Destination: &config.DatabaseURL,
	}

	// HTTPAddressFlag defines the HTTP server listen address
	HTTPAddressFlag = &cli.StringFlag{
		Name:        "http-address",
		Aliases:     []string{"a"},
		Usage:       "HTTP address to listen on",
		Value:       ":8080",
		EnvVars:     []string{"HTTP_ADDRESS"},
		Destination: &config.HTTPAddress,
	}

	// GRPCAddressFlag defines the gRPC server listen address
	GRPCAddressFlag = &cli.StringFlag{
		Name:        "grpc-address",
		Aliases:     []string{"g"},
		Usage:       "gRPC address to listen on",
		Value:       ":9090",
		EnvVars:     []string{"GRPC_ADDRESS"},
		Destination: &config.GRPCAddress,
	}

	// JWTPrivateKeyFlag defines the path to the JWT private key
	JWTIssuerFlag = &cli.StringFlag{
		Name:        "jwt-issuer",
		Usage:       "Name used to identify the principal that issues JWTs",
		Value:       "heimdall",
		EnvVars:     []string{"JWT_PRIVATE_KEY_PATH"},
		Destination: &config.JWTIssuer,
	}

	// JWTPrivateKeyFlag defines the path to the JWT private key
	JWTPrivateKeyFlag = &cli.StringFlag{
		Name:        "jwt-private-key",
		Aliases:     []string{"k"},
		Usage:       "Path to JWT private key file (PEM format)",
		Required:    true,
		EnvVars:     []string{"JWT_PRIVATE_KEY_PATH"},
		Destination: &config.JWTPrivateKeyPath,
	}

	// JWTPublicKeyFlag defines the path to the JWT public key
	JWTPublicKeyFlag = &cli.StringFlag{
		Name:        "jwt-public-key",
		Aliases:     []string{"p"},
		Usage:       "Path to JWT public key file (PEM format)",
		Required:    true,
		EnvVars:     []string{"JWT_PUBLIC_KEY_PATH"},
		Destination: &config.JWTPublicKeyPath,
	}

	// JWTExpirationFlag defines the JWT token expiration duration
	JWTExpirationFlag = &cli.DurationFlag{
		Name:        "jwt-expiration",
		Aliases:     []string{"x"},
		Usage:       "JWT token expiration duration",
		Value:       24 * time.Hour,
		EnvVars:     []string{"JWT_EXPIRATION"},
		Destination: &config.JWTExpiration,
	}

	// EnvironmentFlag defines the deployment environment
	EnvironmentFlag = &cli.StringFlag{
		Name:        "environment",
		Aliases:     []string{"e"},
		Usage:       "Environment (development, staging, production)",
		Value:       "development",
		EnvVars:     []string{"ENVIRONMENT"},
		Destination: &config.Environment,
	}

	// PublicURLFlag defines the public-facing URL
	PublicURLFlag = &cli.StringFlag{
		Name:        "public-url",
		Aliases:     []string{"b"},
		Usage:       "Public-facing URL for email links, OAuth callbacks, and external integrations",
		Value:       "http://localhost:8080",
		EnvVars:     []string{"PUBLIC_URL"},
		Destination: &config.PublicURL,
	}

	// MailmanGRPCAddressFlag defines the mailman gRPC server address
	MailmanGRPCAddressFlag = &cli.StringFlag{
		Name:        "mailman-grpc-address",
		Aliases:     []string{"m"},
		Usage:       "Mailman gRPC server address",
		Value:       "localhost:50051",
		EnvVars:     []string{"MAILMAN_GRPC_ADDRESS"},
		Destination: &config.MailmanGRPCAddress,
	}

	// CORSAllowedOriginsFlag defines allowed CORS origins
	CORSAllowedOriginsFlag = &cli.StringSliceFlag{
		Name:        "cors-allowed-origins",
		Usage:       "Comma-separated list of allowed CORS origins (e.g., http://localhost:5173,http://localhost:3000)",
		EnvVars:     []string{"CORS_ALLOWED_ORIGINS"},
		Destination: &config.CORSAllowedOrigins,
	}

	// EncryptionKeyFlag defines the encryption key for sensitive data
	EncryptionKeyFlag = &cli.StringFlag{
		Name:        "encryption-key",
		Usage:       "AES-256 encryption key for sensitive data (32 bytes, hex-encoded). Use ENCRYPTION_KEY env var instead for security.",
		Required:    true,
		EnvVars:     []string{"ENCRYPTION_KEY"},
		Destination: &config.EncryptionKey,
	}
)
