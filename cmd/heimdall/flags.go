package main

import (
	"time"

	"github.com/urfave/cli/v2"
)

// Common flags that can be reused across commands
var (
	// DebugFlag enables debug logging (global flag)
	DebugFlag = &cli.BoolFlag{
		Name:    "debug",
		Usage:   "Enable debug logging",
		EnvVars: []string{"DEBUG"},
	}

	// DatabaseURLFlag defines the PostgreSQL connection URL (global flag)
	DatabaseURLFlag = &cli.StringFlag{
		Name:    "database-url",
		Aliases: []string{"u"},
		Usage:   "PostgreSQL connection URL",
		Value:   "postgres://heimdall:heimdall_dev_password@localhost:5432/heimdall?sslmode=disable",
		EnvVars: []string{"DATABASE_URL"},
	}

	// HTTPAddressFlag defines the HTTP server listen address
	HTTPAddressFlag = &cli.StringFlag{
		Name:    "http-address",
		Aliases: []string{"a"},
		Usage:   "HTTP address to listen on",
		Value:   ":8080",
		EnvVars: []string{"HTTP_ADDRESS"},
	}

	// GRPCAddressFlag defines the gRPC server listen address
	GRPCAddressFlag = &cli.StringFlag{
		Name:    "grpc-address",
		Aliases: []string{"g"},
		Usage:   "gRPC address to listen on",
		Value:   ":9090",
		EnvVars: []string{"GRPC_ADDRESS"},
	}

	// JWTPrivateKeyFlag defines the path to the JWT private key
	JWTPrivateKeyFlag = &cli.StringFlag{
		Name:     "jwt-private-key",
		Aliases:  []string{"k"},
		Usage:    "Path to JWT private key file (PEM format)",
		Required: true,
		EnvVars:  []string{"JWT_PRIVATE_KEY_PATH"},
	}

	// JWTPublicKeyFlag defines the path to the JWT public key
	JWTPublicKeyFlag = &cli.StringFlag{
		Name:     "jwt-public-key",
		Aliases:  []string{"p"},
		Usage:    "Path to JWT public key file (PEM format)",
		Required: true,
		EnvVars:  []string{"JWT_PUBLIC_KEY_PATH"},
	}

	// JWTExpirationFlag defines the JWT token expiration duration
	JWTExpirationFlag = &cli.DurationFlag{
		Name:    "jwt-expiration",
		Aliases: []string{"x"},
		Usage:   "JWT token expiration duration",
		Value:   24 * time.Hour,
		EnvVars: []string{"JWT_EXPIRATION"},
	}

	// EnvironmentFlag defines the deployment environment
	EnvironmentFlag = &cli.StringFlag{
		Name:    "environment",
		Aliases: []string{"e"},
		Usage:   "Environment (development, staging, production)",
		Value:   "development",
		EnvVars: []string{"ENVIRONMENT"},
	}

	// EmailLinkBaseURLFlag defines the base URL for email links
	EmailLinkBaseURLFlag = &cli.StringFlag{
		Name:    "email-link-base-url",
		Aliases: []string{"b"},
		Usage:   "Base URL for email verification and password reset links",
		Value:   "http://localhost:8080",
		EnvVars: []string{"EMAIL_LINK_BASE_URL"},
	}

	// MailmanGRPCAddressFlag defines the mailman gRPC server address
	MailmanGRPCAddressFlag = &cli.StringFlag{
		Name:    "mailman-grpc-address",
		Aliases: []string{"m"},
		Usage:   "Mailman gRPC server address",
		Value:   "localhost:50051",
		EnvVars: []string{"MAILMAN_GRPC_ADDRESS"},
	}

	// CORSAllowedOriginsFlag defines allowed CORS origins
	CORSAllowedOriginsFlag = &cli.StringSliceFlag{
		Name:    "cors-allowed-origins",
		Usage:   "Comma-separated list of allowed CORS origins (e.g., http://localhost:5173,http://localhost:3000)",
		EnvVars: []string{"CORS_ALLOWED_ORIGINS"},
	}
)
