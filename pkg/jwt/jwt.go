package jwt

import (
	"crypto/rsa"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

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
	return s.createToken(subject, expiresAt, permissions)
}

func (s *JWTService) CreateRefreshToken(subject string) (string, string, error) {
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	return s.createToken(subject, expiresAt, nil)
}

func (s *JWTService) createToken(subject string, expiresAt time.Time, permissions []string) (string, string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", "", err
	}

	csrf, err := uuid.NewRandom()
	if err != nil {
		return "", "", err
	}

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        id.String(),
		},
		CSRF:        csrf.String(),
		Permissions: permissions,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", "", err
	}

	return signedToken, csrf.String(), nil
}

func (s *JWTService) ValidateToken(tokenString, csrf string) (*Claims, error) {
	if csrf == "" {
		return nil, fmt.Errorf("missing CSRF token")
	}

	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, s.publicKey)
	if err != nil {
		return nil, err
	}

	if claims.CSRF != csrf {
		return nil, fmt.Errorf("CSRF tokens do not match")
	}

	return claims, nil
}

func (s *JWTService) publicKey(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
	}

	return &s.privateKey.PublicKey, nil
}
