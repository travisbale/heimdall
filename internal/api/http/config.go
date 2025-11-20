package http

import "context"

type logger interface {
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}

type database interface {
	Health(ctx context.Context) error
}

type Config struct {
	Address            string
	Database           database
	UserService        userService
	OIDCService        oidcService
	RBACService        rbacService
	JWTService         jwtService
	Environment        string
	TrustedProxyMode   bool // Enable when behind trusted reverse proxy (nginx, cloudflare, etc)
	CORSAllowedOrigins []string
	Logger             logger
}

func (c *Config) SecureCookies() bool {
	return c.Environment != "development" && c.Environment != "test"
}
