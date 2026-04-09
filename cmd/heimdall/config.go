package main

import (
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
	EmailWebhookURL    string

	Environment string // "development", "staging", "production"

	TrustedProxyMode bool // Enable IP extraction from proxy headers (X-Forwarded-For)

	EncryptionKey string // AES-256 key for encrypting OIDC client secrets

	CORSAllowedOrigins cli.StringSlice // Browser origins allowed to make requests

	// OAuth provider configuration for individual logins (Google, Microsoft, GitHub)
	GoogleClientID     string
	GoogleClientSecret string
	GoogleIssuerURL    string // Optional: override for testing (defaults to https://accounts.google.com)

	MicrosoftClientID     string
	MicrosoftClientSecret string
	MicrosoftTenantID     string // Optional: defaults to "common"
	MicrosoftIssuerURL    string // Optional: override for testing

	GitHubClientID     string
	GitHubClientSecret string
	GitHubAuthURL      string // Optional: override for testing
	GitHubTokenURL     string // Optional: override for testing
	GitHubAPIBase      string // Optional: override for testing (defaults to https://api.github.com)

	TOTPPeriod uint // TOTP time window in seconds (default 30, use smaller value for testing)
}

var config = &Config{}

// ToAppConfig converts CLI config to internal app config
func (c *Config) ToAppConfig() *app.Config {
	return &app.Config{
		DatabaseURL:           c.DatabaseURL,
		HTTPAddress:           c.HTTPAddress,
		GRPCAddress:           c.GRPCAddress,
		JWTIssuer:             c.JWTIssuer,
		JWTPrivateKeyPath:     c.JWTPrivateKeyPath,
		JWTPublicKeyPath:      c.JWTPublicKeyPath,
		JWTExpiration:         c.JWTExpiration,
		PublicURL:             c.PublicURL,
		MailmanGRPCAddress:    c.MailmanGRPCAddress,
		EmailWebhookURL:       c.EmailWebhookURL,
		Environment:           c.Environment,
		TrustedProxyMode:      c.TrustedProxyMode,
		EncryptionKey:         c.EncryptionKey,
		CORSAllowedOrigins:    c.CORSAllowedOrigins.Value(),
		GoogleClientID:        c.GoogleClientID,
		GoogleClientSecret:    c.GoogleClientSecret,
		GoogleIssuerURL:       c.GoogleIssuerURL,
		MicrosoftClientID:     c.MicrosoftClientID,
		MicrosoftClientSecret: c.MicrosoftClientSecret,
		MicrosoftTenantID:     c.MicrosoftTenantID,
		MicrosoftIssuerURL:    c.MicrosoftIssuerURL,
		GitHubClientID:        c.GitHubClientID,
		GitHubClientSecret:    c.GitHubClientSecret,
		GitHubAuthURL:         c.GitHubAuthURL,
		GitHubTokenURL:        c.GitHubTokenURL,
		GitHubAPIBase:         c.GitHubAPIBase,
		TOTPPeriod:            c.TOTPPeriod,
	}
}
