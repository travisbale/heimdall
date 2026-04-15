package util

import (
	"os"
	"path/filepath"
	"runtime"
)

// Config holds test infrastructure connection details
type Config struct {
	HeimdallBaseURL     string
	HeimdallGRPCAddress string
	OIDCMockURL         string // Reachable from tests (host network)
	OIDCMockInternalURL string // Reachable from heimdall (Docker network), used as issuer URL when creating providers
	JWTPublicKeyPath    string
}

// LoadConfig loads test configuration from environment variables with defaults.
// Defaults point to local docker-compose infrastructure.
func LoadConfig() *Config {
	return &Config{
		HeimdallBaseURL:     getEnv("HEIMDALL_BASE_URL", "http://localhost:8080"),
		HeimdallGRPCAddress: getEnv("HEIMDALL_GRPC_ADDRESS", "localhost:9090"),
		OIDCMockURL:         getEnv("OIDC_MOCK_URL", "http://localhost:8082"),
		OIDCMockInternalURL: getEnv("OIDC_MOCK_INTERNAL_URL", "http://heimdall-oidc-mock-test:8082"),
		JWTPublicKeyPath:    getEnv("JWT_PUBLIC_KEY_PATH", jwtPublicKeyPath()),
	}
}

func jwtPublicKeyPath() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "keys", "public-key.pem")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
