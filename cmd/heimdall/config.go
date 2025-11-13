package main

import (
	"log/slog"
	"time"

	"github.com/travisbale/heimdall/internal/app"
	"github.com/urfave/cli/v2"
)

// Config holds all CLI configuration, populated from flags and environment variables
type Config struct {
	Debug     bool
	LogFormat string

	DatabaseURL string

	HTTPAddress string
	GRPCAddress string

	JWTIssuer         string
	JWTPrivateKeyPath string
	JWTPublicKeyPath  string
	JWTExpiration     time.Duration

	PublicURL string

	MailmanGRPCAddress string

	Environment string // "development", "staging", "production"

	EncryptionKey string // AES-256 key for encrypting OIDC client secrets

	CORSAllowedOrigins cli.StringSlice // Browser origins allowed to make requests
}

var config = &Config{}

// ToAppConfig converts CLI config to internal app config
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
