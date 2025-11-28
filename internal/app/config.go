package app

import (
	"time"

	"github.com/travisbale/knowhere/crypto/argon2"
)

const (
	// Argon2 production parameters (OWASP recommended for password hashing)
	argon2ProductionIterations = 2         // Number of iterations
	argon2ProductionMemory     = 64 * 1024 // Memory in KiB (64 MB)

	// Argon2 test parameters (faster for testing, still secure enough)
	argon2TestIterations = 1        // Number of iterations
	argon2TestMemory     = 8 * 1024 // Memory in KiB (8 MB)

	// Common parameters for both environments
	argon2Threads   = 4  // Number of threads
	argon2KeyLength = 32 // Length of the generated key in bytes
	saltLength      = 16 // Length of the salt in bytes
)

// Config holds the configuration for creating a new server
type Config struct {
	HTTPAddress        string
	GRPCAddress        string
	DatabaseURL        string
	JWTIssuer          string
	JWTPrivateKeyPath  string
	JWTPublicKeyPath   string
	JWTExpiration      time.Duration
	PublicURL          string
	MailmanGRPCAddress string
	Environment        string
	EncryptionKey      string
	TrustedProxyMode   bool // Enable IP extraction from X-Forwarded-For when behind reverse proxy
	CORSAllowedOrigins []string

	// OAuth provider configuration for individual logins
	GoogleClientID     string
	GoogleClientSecret string
	GoogleIssuerURL    string

	MicrosoftClientID     string
	MicrosoftClientSecret string
	MicrosoftTenantID     string
	MicrosoftIssuerURL    string

	GitHubClientID     string
	GitHubClientSecret string
	GitHubAuthURL      string
	GitHubTokenURL     string
	GitHubAPIBase      string

	TOTPPeriod uint // TOTP time window in seconds (default 30, use smaller value for tests)
}

// getArgon2Config returns Argon2 parameters based on environment
// Uses lighter parameters for test/development to speed up tests
func getArgon2Config(environment string) *argon2.Config {
	// Use test parameters for faster hashing in test/development environments
	if environment == "test" || environment == "development" {
		return &argon2.Config{
			Memory:      argon2TestMemory,
			Iterations:  argon2TestIterations,
			SaltLength:  saltLength,
			KeyLength:   argon2KeyLength,
			Parallelism: argon2Threads,
		}
	}

	// Use production parameters for staging/production
	return &argon2.Config{
		Memory:      argon2ProductionMemory,
		Iterations:  argon2ProductionIterations,
		SaltLength:  saltLength,
		KeyLength:   argon2KeyLength,
		Parallelism: argon2Threads,
	}
}
