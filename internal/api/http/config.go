package http

type Config struct {
	Address            string
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
