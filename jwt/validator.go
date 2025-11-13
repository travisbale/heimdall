package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	// ErrInvalidToken is returned when the token is invalid
	ErrInvalidToken = errors.New("invalid token")
	// ErrMissingClaims is returned when expected claims are missing
	ErrMissingClaims = errors.New("missing required claims")
)

// Validator handles JWT validation
type Validator struct {
	publicKey *rsa.PublicKey
}

// NewValidator creates a new JWT validator with the provided RSA public key
func NewValidator(publicKeyPath string) (*Validator, error) {
	publicKeyFile, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &Validator{
		publicKey: publicKey,
	}, nil
}

// ValidateToken validates a JWT token string and returns the claims
// Checks signature, expiration, and presence of required tenant/user claims
func (v *Validator) ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, v.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Ensure multi-tenant context is present
	if claims.Subject == "" || claims.TenantID == uuid.Nil {
		return nil, ErrMissingClaims
	}

	return claims, nil
}

func (v *Validator) keyFunc(token *jwt.Token) (any, error) {
	// Reject tokens signed with algorithms other than RSA
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return v.publicKey, nil
}
