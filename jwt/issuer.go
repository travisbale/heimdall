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
	AudienceMFASetup     = "heimdall:mfa-setup"     // Temporary tokens for required MFA setup
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
	mfaSetupTokenExpiration     time.Duration
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
		mfaSetupTokenExpiration:     config.MFASetupTokenExpiration,
	}, nil
}

// IssueAccessToken creates short-lived token for API requests
func (i *Issuer) IssueAccessToken(tenantID, userID uuid.UUID, scopes []sdk.Scope) (string, time.Duration, error) {
	expiresAt := time.Now().Add(i.accessTokenExpiration)
	token, err := i.issueToken(AudienceAPI, tenantID, userID, scopes, expiresAt)
	return token, i.accessTokenExpiration, err
}

// IssueRefreshToken creates long-lived token for obtaining new access tokens
func (i *Issuer) IssueRefreshToken(tenantID, userID uuid.UUID) (string, time.Duration, error) {
	expiresAt := time.Now().Add(i.refreshTokenExpiration)
	token, err := i.issueToken(AudienceAPI, tenantID, userID, nil, expiresAt)
	return token, i.refreshTokenExpiration, err
}

// IssueMFAChallengeToken creates a short-lived token for MFA verification
func (i *Issuer) IssueMFAChallengeToken(tenantID, userID uuid.UUID) (string, time.Duration, error) {
	expiresAt := time.Now().Add(i.mfaChallengeTokenExpiration)
	token, err := i.issueToken(AudienceMFAChallenge, tenantID, userID, nil, expiresAt)
	return token, i.mfaChallengeTokenExpiration, err
}

// IssueMFASetupToken creates a short-lived token for required MFA setup
func (i *Issuer) IssueMFASetupToken(tenantID, userID uuid.UUID) (string, time.Duration, error) {
	expiresAt := time.Now().Add(i.mfaSetupTokenExpiration)
	token, err := i.issueToken(AudienceMFASetup, tenantID, userID, nil, expiresAt)
	return token, i.mfaSetupTokenExpiration, err
}

func (i *Issuer) issueToken(audience string, tenantID, userID uuid.UUID, scopes []sdk.Scope, expiresAt time.Time) (string, error) {
	now := time.Now()

	claims := &Claims{
		UserID:   userID,
		TenantID: tenantID,
		Scopes:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(), // Unique token ID prevents hash collisions
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
