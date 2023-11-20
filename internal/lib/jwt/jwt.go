package jwt

import (
	"crypto/rsa"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type claims struct {
	jwt.RegisteredClaims
	CSRF        string   `json:"csrf"`
	Type        string   `json:"type"`
	Permissions []string `json:"permissions,omitempty"`
}

type JWTService struct {
	issuer     string
	privateKey *rsa.PrivateKey
}

func NewJWTService(issuer string, privateKeyFile []byte) (*JWTService, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key file: %w", err)
	}

	return &JWTService{
		issuer:     issuer,
		privateKey: privateKey,
	}, nil
}

func (s *JWTService) CreateAccessToken(subject string, permissions []string) (string, string, error) {
	expiresAt := time.Now().Add(15 * time.Minute)
	return s.createToken(subject, "access", expiresAt, permissions)
}

func (s *JWTService) CreateRefreshToken(subject string) (string, string, error) {
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	return s.createToken(subject, "refresh", expiresAt, nil)
}

func (s *JWTService) createToken(subject, tokenType string, expiresAt time.Time, permissions []string) (string, string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", "", err
	}

	csrf, err := uuid.NewRandom()
	if err != nil {
		return "", "", err
	}

	claims := &claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        id.String(),
		},
		CSRF:        csrf.String(),
		Type:        tokenType,
		Permissions: permissions,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", "", err
	}

	return signedToken, csrf.String(), nil
}
