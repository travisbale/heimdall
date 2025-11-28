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
		Usage:       "PostgreSQL connection URL",
		Value:       "postgres://heimdall:heimdall_dev_password@localhost:5432/heimdall?sslmode=disable",
		EnvVars:     []string{"DATABASE_URL"},
		Destination: &config.DatabaseURL,
	}

	HTTPAddressFlag = &cli.StringFlag{
		Name:        "http-address",
		Usage:       "HTTP address to listen on",
		Value:       ":8080",
		EnvVars:     []string{"HTTP_ADDRESS"},
		Destination: &config.HTTPAddress,
	}

	GRPCAddressFlag = &cli.StringFlag{
		Name:        "grpc-address",
		Usage:       "gRPC address to listen on",
		Value:       ":9090",
		EnvVars:     []string{"GRPC_ADDRESS"},
		Destination: &config.GRPCAddress,
	}

	JWTIssuerFlag = &cli.StringFlag{
		Name:        "jwt-issuer",
		Usage:       "Name used to identify the principal that issues JWTs",
		Value:       "heimdall",
		EnvVars:     []string{"JWT_PRIVATE_KEY_PATH"},
		Destination: &config.JWTIssuer,
	}

	JWTPrivateKeyFlag = &cli.StringFlag{
		Name:        "jwt-private-key",
		Usage:       "Path to JWT private key file (PEM format)",
		Required:    true,
		EnvVars:     []string{"JWT_PRIVATE_KEY_PATH"},
		Destination: &config.JWTPrivateKeyPath,
	}

	JWTPublicKeyFlag = &cli.StringFlag{
		Name:        "jwt-public-key",
		Usage:       "Path to JWT public key file (PEM format)",
		Required:    true,
		EnvVars:     []string{"JWT_PUBLIC_KEY_PATH"},
		Destination: &config.JWTPublicKeyPath,
	}

	JWTExpirationFlag = &cli.DurationFlag{
		Name:        "jwt-expiration",
		Usage:       "JWT token expiration duration",
		Value:       24 * time.Hour,
		EnvVars:     []string{"JWT_EXPIRATION"},
		Destination: &config.JWTExpiration,
	}

	EnvironmentFlag = &cli.StringFlag{
		Name:        "environment",
		Aliases:     []string{"e"},
		Usage:       "Environment (development, staging, production)",
		Value:       "development",
		EnvVars:     []string{"ENVIRONMENT"},
		Destination: &config.Environment,
	}

	PublicURLFlag = &cli.StringFlag{
		Name:        "public-url",
		Usage:       "Public-facing URL for email links, OAuth callbacks, and external integrations",
		Value:       "http://localhost:8080",
		EnvVars:     []string{"PUBLIC_URL"},
		Destination: &config.PublicURL,
	}

	MailmanGRPCAddressFlag = &cli.StringFlag{
		Name:        "mailman-grpc-address",
		Usage:       "Mailman gRPC server address",
		Value:       "localhost:50051",
		EnvVars:     []string{"MAILMAN_GRPC_ADDRESS"},
		Destination: &config.MailmanGRPCAddress,
	}

	UatuGRPCAddressFlag = &cli.StringFlag{
		Name:        "uatu-grpc-address",
		Usage:       "Uatu audit logging gRPC server address",
		Value:       "localhost:9091",
		EnvVars:     []string{"UATU_GRPC_ADDRESS"},
		Destination: &config.UatuGRPCAddress,
	}

	TrustedProxyModeFlag = &cli.BoolFlag{
		Name:        "trusted-proxy-mode",
		Usage:       "Enable IP extraction from X-Forwarded-For when behind trusted reverse proxy (nginx, cloudflare, etc). Security warning: only enable if proxy strips/validates headers.",
		Value:       false,
		EnvVars:     []string{"TRUSTED_PROXY_MODE"},
		Destination: &config.TrustedProxyMode,
	}

	CORSAllowedOriginsFlag = &cli.StringSliceFlag{
		Name:        "cors-allowed-origins",
		Usage:       "Comma-separated list of allowed CORS origins (e.g., http://localhost:5173,http://localhost:3000)",
		EnvVars:     []string{"CORS_ALLOWED_ORIGINS"},
		Destination: &config.CORSAllowedOrigins,
	}

	EncryptionKeyFlag = &cli.StringFlag{
		Name:        "encryption-key",
		Usage:       "AES-256 encryption key for sensitive data (32 bytes, hex-encoded). Use ENCRYPTION_KEY env var instead for security.",
		Required:    true,
		EnvVars:     []string{"ENCRYPTION_KEY"},
		Destination: &config.EncryptionKey,
	}

	// Google OAuth provider flags
	GoogleClientIDFlag = &cli.StringFlag{
		Name:        "google-client-id",
		Usage:       "Google OAuth client ID for individual login",
		EnvVars:     []string{"GOOGLE_CLIENT_ID"},
		Destination: &config.GoogleClientID,
	}

	GoogleClientSecretFlag = &cli.StringFlag{
		Name:        "google-client-secret",
		Usage:       "Google OAuth client secret",
		EnvVars:     []string{"GOOGLE_CLIENT_SECRET"},
		Destination: &config.GoogleClientSecret,
	}

	GoogleIssuerURLFlag = &cli.StringFlag{
		Name:        "google-issuer-url",
		Usage:       "Google OIDC issuer URL (optional, defaults to https://accounts.google.com, mainly for testing)",
		EnvVars:     []string{"GOOGLE_ISSUER_URL"},
		Destination: &config.GoogleIssuerURL,
	}

	// Microsoft OAuth provider flags
	MicrosoftClientIDFlag = &cli.StringFlag{
		Name:        "microsoft-client-id",
		Usage:       "Microsoft OAuth client ID for individual login",
		EnvVars:     []string{"MICROSOFT_CLIENT_ID"},
		Destination: &config.MicrosoftClientID,
	}

	MicrosoftClientSecretFlag = &cli.StringFlag{
		Name:        "microsoft-client-secret",
		Usage:       "Microsoft OAuth client secret",
		EnvVars:     []string{"MICROSOFT_CLIENT_SECRET"},
		Destination: &config.MicrosoftClientSecret,
	}

	MicrosoftTenantIDFlag = &cli.StringFlag{
		Name:        "microsoft-tenant-id",
		Usage:       "Microsoft Azure AD tenant ID (defaults to 'common' for multi-tenant)",
		Value:       "common",
		EnvVars:     []string{"MICROSOFT_TENANT_ID"},
		Destination: &config.MicrosoftTenantID,
	}

	MicrosoftIssuerURLFlag = &cli.StringFlag{
		Name:        "microsoft-issuer-url",
		Usage:       "Microsoft OIDC issuer URL (optional, mainly for testing)",
		EnvVars:     []string{"MICROSOFT_ISSUER_URL"},
		Destination: &config.MicrosoftIssuerURL,
	}

	// GitHub OAuth provider flags
	GitHubClientIDFlag = &cli.StringFlag{
		Name:        "github-client-id",
		Usage:       "GitHub OAuth client ID for individual login",
		EnvVars:     []string{"GITHUB_CLIENT_ID"},
		Destination: &config.GitHubClientID,
	}

	GitHubClientSecretFlag = &cli.StringFlag{
		Name:        "github-client-secret",
		Usage:       "GitHub OAuth client secret",
		EnvVars:     []string{"GITHUB_CLIENT_SECRET"},
		Destination: &config.GitHubClientSecret,
	}

	GitHubAuthURLFlag = &cli.StringFlag{
		Name:        "github-auth-url",
		Usage:       "GitHub OAuth authorization URL (optional, mainly for testing)",
		EnvVars:     []string{"GITHUB_AUTH_URL"},
		Destination: &config.GitHubAuthURL,
	}

	GitHubTokenURLFlag = &cli.StringFlag{
		Name:        "github-token-url",
		Usage:       "GitHub OAuth token URL (optional, mainly for testing)",
		EnvVars:     []string{"GITHUB_TOKEN_URL"},
		Destination: &config.GitHubTokenURL,
	}

	GitHubAPIBaseFlag = &cli.StringFlag{
		Name:        "github-api-base",
		Usage:       "GitHub API base URL (optional, defaults to https://api.github.com, mainly for testing)",
		EnvVars:     []string{"GITHUB_API_BASE"},
		Destination: &config.GitHubAPIBase,
	}

	TOTPPeriodFlag = &cli.UintFlag{
		Name:        "totp-period",
		Usage:       "TOTP time window in seconds (default 30, use smaller value for testing)",
		EnvVars:     []string{"TOTP_PERIOD"},
		Value:       30,
		Destination: &config.TOTPPeriod,
	}
)
