package jwt

import (
	"crypto/rsa"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents the JWT claims structure
type Claims struct {
	jwt.RegisteredClaims
	TenantID    uuid.UUID `json:"tenant_id"`
	Permissions []string  `json:"permissions,omitempty"`
}

// Issuer handles JWT token generation
type Issuer struct {
	issuer                 string
	privateKey             *rsa.PrivateKey
	accessTokenExpiration  time.Duration
	refreshTokenExpiration time.Duration
}

// NewIssuer creates a new JWT issuer with the provided RSA private key
func NewIssuer(config *Config) (*Issuer, error) {
	privateKeyFile, err := os.ReadFile(config.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %w", err)
	}

	return &Issuer{
		issuer:                 config.Issuer,
		privateKey:             privateKey,
		accessTokenExpiration:  config.AccessTokenExpiration,
		refreshTokenExpiration: config.RefreshTokenExpiration,
	}, nil
}

func (i *Issuer) IssueAccessToken(userID, tenantID uuid.UUID, permissions []string) (string, error) {
	expiresAt := time.Now().Add(i.accessTokenExpiration)
	return i.issueToken(userID, tenantID, expiresAt, permissions)
}

func (i *Issuer) IssueRefreshToken(userID, tenantID uuid.UUID) (string, error) {
	expiresAt := time.Now().Add(i.refreshTokenExpiration)
	return i.issueToken(userID, tenantID, expiresAt, nil)
}

// GetRefreshTokenExpiration returns the refresh token expiration duration
func (i *Issuer) GetRefreshTokenExpiration() time.Duration {
	return i.refreshTokenExpiration
}

// IssueToken generates a new JWT token for the user
func (i *Issuer) issueToken(userID, tenantID uuid.UUID, expiresAt time.Time, permissions []string) (string, error) {
	now := time.Now()
	claims := &Claims{
		TenantID:    tenantID,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(i.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}
