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
// Checks signature, expiration, audience (must be heimdall:api), and presence of required claims
func (v *Validator) ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	if token, err := jwt.ParseWithClaims(tokenString, claims, v.keyFunc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	} else if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Verify token is an API token, not an MFA challenge token
	hasCorrectAudience := false
	for _, aud := range claims.Audience {
		if aud == AudienceAPI {
			hasCorrectAudience = true
			break
		}
	}
	if !hasCorrectAudience {
		return nil, ErrInvalidAudience
	}

	// Ensure multi-tenant context is present
	if claims.Subject == "" || claims.TenantID == uuid.Nil {
		return nil, ErrMissingClaims
	}

	return claims, nil
}

// ValidateMFAChallengeToken validates an MFA challenge token and returns the claims
// These tokens are short-lived and can ONLY be used for MFA verification endpoints
func (v *Validator) ValidateMFAChallengeToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	if token, err := jwt.ParseWithClaims(tokenString, claims, v.keyFunc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	} else if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Verify token is an MFA challenge token, not a regular API token
	hasCorrectAudience := false
	for _, aud := range claims.Audience {
		if aud == AudienceMFAChallenge {
			hasCorrectAudience = true
			break
		}
	}
	if !hasCorrectAudience {
		return nil, ErrInvalidAudience
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
