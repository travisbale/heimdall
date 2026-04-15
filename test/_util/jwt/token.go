package jwt

import (
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	util "github.com/travisbale/heimdall/test/_util"
	"github.com/travisbale/knowhere/jwt"
)

var (
	validator     *jwt.Validator
	validatorErr  error
	validatorOnce sync.Once
)

func getValidator(t *testing.T) *jwt.Validator {
	t.Helper()

	validatorOnce.Do(func() {
		config := util.LoadConfig()
		validator, validatorErr = jwt.NewValidator(config.JWTPublicKeyPath)
	})

	require.NoError(t, validatorErr, "failed to create JWT validator")
	return validator
}

// ExtractClaims validates a token and returns its claims
func ExtractClaims(t *testing.T, token string) *jwt.Claims {
	t.Helper()
	claims, err := getValidator(t).ValidateToken(token)
	require.NoError(t, err, "failed to validate token")
	return claims
}

// ExtractMFAChallengeClaims validates an MFA challenge token and returns its claims
func ExtractMFAChallengeClaims(t *testing.T, token string) *jwt.Claims {
	t.Helper()
	claims, err := getValidator(t).ValidateMFAChallengeToken(token)
	require.NoError(t, err, "failed to validate MFA challenge token")
	return claims
}

// ExtractMFASetupAudience validates an MFA setup token and returns the audience
func ExtractMFASetupAudience(t *testing.T, token string) []string {
	t.Helper()
	claims, err := getValidator(t).ValidateMFASetupToken(token)
	require.NoError(t, err, "failed to validate MFA setup token")
	return claims.Audience
}

// ExtractUserID validates a JWT and returns the user ID
func ExtractUserID(t *testing.T, token string) uuid.UUID {
	t.Helper()
	return ExtractClaims(t, token).UserID
}

// ExtractTenantID validates a JWT and returns the tenant ID
func ExtractTenantID(t *testing.T, token string) uuid.UUID {
	t.Helper()
	return ExtractClaims(t, token).TenantID
}
