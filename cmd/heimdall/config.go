package main

import (
	"log/slog"
	"time"

	"github.com/travisbale/heimdall/internal/app"
	"github.com/urfave/cli/v2"
)

// Config holds all configuration for the application
type Config struct {
	// Debug
	Debug bool

	// Database
	DatabaseURL string

	// Server addresses
	HTTPAddress string
	GRPCAddress string

	// JWT configuration
	JWTIssuer         string
	JWTPrivateKeyPath string
	JWTPublicKeyPath  string
	JWTExpiration     time.Duration

	// Public URL
	PublicURL string

	// Email configuration
	MailmanGRPCAddress string

	// Environment
	Environment string

	// Encryption
	EncryptionKey string

	// CORS (cli.StringSlice since it needs special handling)
	CORSAllowedOrigins cli.StringSlice
}

// config is the global configuration populated by CLI flags
var config = &Config{}

// ToAppConfig converts the CLI config to an app.Config
func (c *Config) ToAppConfig() *app.Config {
	return &app.Config{
		DatabaseURL:        c.DatabaseURL,
		HTTPAddress:        c.HTTPAddress,
		GRPCAddress:        c.GRPCAddress,
		JWTIssuer:          c.JWTIssuer,
		JWTPrivateKeyPath:  c.JWTPrivateKeyPath,
		JWTPublicKeyPath:   c.JWTPublicKeyPath,
		JWTExpiration:      c.JWTExpiration,
		PublicURL:          c.PublicURL,
		MailmanGRPCAddress: c.MailmanGRPCAddress,
		Environment:        c.Environment,
		EncryptionKey:      c.EncryptionKey,
		CORSAllowedOrigins: c.CORSAllowedOrigins.Value(),
		Logger:             slog.Default(),
	}
}
