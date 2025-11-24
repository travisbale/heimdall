package jwt

import (
	"crypto/rsa"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// Token audiences for different token types
const (
	AudienceAPI          = "heimdall:api"           // Regular access tokens for API requests
	AudienceMFAChallenge = "heimdall:mfa-challenge" // Temporary tokens for MFA verification
)

// Claims represents the JWT claims structure
type Claims struct {
	jwt.RegisteredClaims
	UserID   uuid.UUID   `json:"user_id"`
	TenantID uuid.UUID   `json:"tenant_id"`
	Scopes   []sdk.Scope `json:"scopes,omitempty"`
}

// Issuer handles JWT token generation
type Issuer struct {
	issuer                      string
	privateKey                  *rsa.PrivateKey
	accessTokenExpiration       time.Duration
	refreshTokenExpiration      time.Duration
	mfaChallengeTokenExpiration time.Duration
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
		issuer:                      config.Issuer,
		privateKey:                  privateKey,
		accessTokenExpiration:       config.AccessTokenExpiration,
		refreshTokenExpiration:      config.RefreshTokenExpiration,
		mfaChallengeTokenExpiration: config.MFAChallengeTokenExpiration,
	}, nil
}

// IssueAccessToken creates short-lived token for API requests
func (i *Issuer) IssueAccessToken(tenantID, userID uuid.UUID, scopes []sdk.Scope) (string, error) {
	expiresAt := time.Now().Add(i.accessTokenExpiration)
	return i.issueToken(AudienceAPI, tenantID, userID, scopes, expiresAt)
}

// IssueRefreshToken creates long-lived token for obtaining new access tokens
func (i *Issuer) IssueRefreshToken(tenantID, userID uuid.UUID) (string, error) {
	expiresAt := time.Now().Add(i.refreshTokenExpiration)
	return i.issueToken(AudienceAPI, tenantID, userID, nil, expiresAt)
}

// IssueMFAChallengeToken creates a short-lived token for MFA verification
func (i *Issuer) IssueMFAChallengeToken(tenantID, userID uuid.UUID) (string, error) {
	expiresAt := time.Now().Add(i.mfaChallengeTokenExpiration)
	return i.issueToken(AudienceMFAChallenge, tenantID, userID, nil, expiresAt)
}

func (i *Issuer) issueToken(audience string, tenantID, userID uuid.UUID, scopes []sdk.Scope, expiresAt time.Time) (string, error) {
	now := time.Now()

	claims := &Claims{
		UserID:   userID,
		TenantID: tenantID,
		Scopes:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{audience},
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

// GetAccessTokenExpiration returns the access token expiration duration
func (i *Issuer) GetAccessTokenExpiration() time.Duration {
	return i.accessTokenExpiration
}

// GetRefreshTokenExpiration returns the refresh token expiration duration
func (i *Issuer) GetRefreshTokenExpiration() time.Duration {
	return i.refreshTokenExpiration
}

// GetMFAChallengeTokenExpiration returns the MFA challenge token expiration duration
func (i *Issuer) GetMFAChallengeTokenExpiration() time.Duration {
	return i.mfaChallengeTokenExpiration
}
