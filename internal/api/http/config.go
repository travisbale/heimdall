package http

import (
	"context"

	"github.com/travisbale/heimdall/internal/iam"
)

// logger provides structured logging capabilities (matches *slog.Logger)
type logger interface {
	InfoContext(ctx context.Context, msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
}

type database interface {
	Health(ctx context.Context) error
}

type jwtValidator interface {
	ValidateToken(token string) (*iam.JWTClaims, error)
}

type Config struct {
	Address             string
	Database            database
	UserService         userService
	PasswordService     passwordService
	MFAService          mfaService
	OIDCAuthService     oidcAuthService
	OIDCProviderService oidcProviderService
	RBACService         rbacService
	AuthService         authService
	SessionService      sessionService
	JWTValidator        jwtValidator
	Environment         string
	TrustedProxyMode    bool // Enable when behind trusted reverse proxy (nginx, cloudflare, etc)
	CORSAllowedOrigins  []string
	Logger              logger
}

func (c *Config) SecureCookies() bool {
	return c.Environment != "development" && c.Environment != "test"
}
