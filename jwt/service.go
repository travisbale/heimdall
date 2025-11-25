package jwt

import (
	"fmt"
	"time"
)

type Config struct {
	Issuer                      string
	PrivateKeyPath              string
	PublicKeyPath               string
	AccessTokenExpiration       time.Duration
	RefreshTokenExpiration      time.Duration
	MFAChallengeTokenExpiration time.Duration
	MFASetupTokenExpiration     time.Duration
}

// Service combines issuing and validating JWTs using asymmetric RSA keys
type Service struct {
	*Issuer
	*Validator
}

func NewService(config *Config) (*Service, error) {
	issuer, err := NewIssuer(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT issuer: %w", err)
	}

	validator, err := NewValidator(config.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT validator: %w", err)
	}

	return &Service{
		Issuer:    issuer,
		Validator: validator,
	}, nil
}
