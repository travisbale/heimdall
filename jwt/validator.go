package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrMissingClaims   = errors.New("missing required claims")
	ErrInvalidAudience = errors.New("invalid token audience")
	ErrWrongTokenType  = errors.New("wrong token type for this operation")
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

// ValidateToken validates a JWT access/refresh token and returns the claims
func (v *Validator) ValidateToken(tokenString string) (*Claims, error) {
	return v.validateToken(AudienceAPI, tokenString)
}

// ValidateMFAChallengeToken validates an MFA challenge token and returns the claims
func (v *Validator) ValidateMFAChallengeToken(tokenString string) (*Claims, error) {
	return v.validateToken(AudienceMFAChallenge, tokenString)
}

// ValidateMFASetupToken validates an MFA setup token and returns the claims
func (v *Validator) ValidateMFASetupToken(tokenString string) (*Claims, error) {
	return v.validateToken(AudienceMFASetup, tokenString)
}

// validateToken validates a token and confirms the target audience is correct
func (v *Validator) validateToken(audience, tokenString string) (*Claims, error) {
	claims := &Claims{}
	if token, err := jwt.ParseWithClaims(tokenString, claims, v.keyFunc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	} else if !token.Valid {
		return nil, ErrInvalidToken
	}

	if !slices.Contains(claims.Audience, audience) {
		return nil, ErrInvalidAudience
	}

	if claims.Subject == "" || claims.UserID == uuid.Nil || claims.TenantID == uuid.Nil {
		return nil, ErrMissingClaims
	}

	return claims, nil
}

// keyFunc rejects tokens signed with algorithms other than RSA
func (v *Validator) keyFunc(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return v.publicKey, nil
}
