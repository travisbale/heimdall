package sdk

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginRequest_Validate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid request", func(t *testing.T) {
		req := LoginRequest{Email: "user@example.com", Password: "password"}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("missing email", func(t *testing.T) {
		req := LoginRequest{Password: "password"}
		assert.Error(t, req.Validate(ctx))
	})

	t.Run("invalid email format", func(t *testing.T) {
		req := LoginRequest{Email: "not-an-email", Password: "password"}
		assert.Error(t, req.Validate(ctx))
	})

	t.Run("missing password", func(t *testing.T) {
		req := LoginRequest{Email: "user@example.com"}
		assert.Error(t, req.Validate(ctx))
	})
}

func TestRegisterRequest_Validate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid request", func(t *testing.T) {
		req := RegisterRequest{Email: "user@example.com", FirstName: "Test", LastName: "User"}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("missing email", func(t *testing.T) {
		req := RegisterRequest{FirstName: "Test", LastName: "User"}
		assert.Error(t, req.Validate(ctx))
	})

	t.Run("missing first name", func(t *testing.T) {
		req := RegisterRequest{Email: "user@example.com", LastName: "User"}
		assert.Error(t, req.Validate(ctx))
	})

	t.Run("missing last name", func(t *testing.T) {
		req := RegisterRequest{Email: "user@example.com", FirstName: "Test"}
		assert.Error(t, req.Validate(ctx))
	})
}

func TestVerifyEmailRequest_Validate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid request", func(t *testing.T) {
		req := VerifyEmailRequest{Token: "abc123", Password: "Xe9#mK2pLq!vR4"}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("missing token", func(t *testing.T) {
		req := VerifyEmailRequest{Password: "Xe9#mK2pLq!vR4"}
		assert.Error(t, req.Validate(ctx))
	})

	t.Run("missing password", func(t *testing.T) {
		req := VerifyEmailRequest{Token: "abc123"}
		assert.Error(t, req.Validate(ctx))
	})

	t.Run("weak password", func(t *testing.T) {
		req := VerifyEmailRequest{Token: "abc123", Password: "short"}
		assert.Error(t, req.Validate(ctx))
	})
}

func TestResetPasswordRequest_Validate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid request", func(t *testing.T) {
		req := ResetPasswordRequest{Token: "abc123", NewPassword: "Xe9#mK2pLq!vR4"}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("missing token", func(t *testing.T) {
		req := ResetPasswordRequest{NewPassword: "Xe9#mK2pLq!vR4"}
		assert.Error(t, req.Validate(ctx))
	})

	t.Run("weak password", func(t *testing.T) {
		req := ResetPasswordRequest{Token: "abc123", NewPassword: "weak"}
		assert.Error(t, req.Validate(ctx))
	})
}

func TestEnableMFARequest_Validate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid 6-digit code", func(t *testing.T) {
		req := EnableMFARequest{Code: "123456"}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("missing code", func(t *testing.T) {
		req := EnableMFARequest{}
		assert.Error(t, req.Validate(ctx))
	})

	t.Run("wrong length code", func(t *testing.T) {
		req := EnableMFARequest{Code: "12345"}
		assert.Error(t, req.Validate(ctx))
	})
}

func TestVerifyMFACodeRequest_Validate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid TOTP code", func(t *testing.T) {
		req := VerifyMFACodeRequest{ChallengeToken: "token", Code: "123456"}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("valid backup code", func(t *testing.T) {
		req := VerifyMFACodeRequest{ChallengeToken: "token", Code: "12345678"}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("missing challenge token", func(t *testing.T) {
		req := VerifyMFACodeRequest{Code: "123456"}
		assert.Error(t, req.Validate(ctx))
	})

	t.Run("missing code", func(t *testing.T) {
		req := VerifyMFACodeRequest{ChallengeToken: "token"}
		assert.Error(t, req.Validate(ctx))
	})

	t.Run("invalid code length", func(t *testing.T) {
		req := VerifyMFACodeRequest{ChallengeToken: "token", Code: "1234"}
		assert.Error(t, req.Validate(ctx))
	})
}

func TestCreateOIDCProviderRequest_Validate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid manual registration", func(t *testing.T) {
		req := CreateOIDCProviderRequest{
			ProviderName:   "Test",
			IssuerURL:      "https://idp.example.com",
			ClientID:       "id",
			ClientSecret:   "secret",
			AllowedDomains: []string{"example.com"},
		}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("valid dynamic registration", func(t *testing.T) {
		req := CreateOIDCProviderRequest{
			ProviderName:   "Test",
			IssuerURL:      "https://idp.example.com",
			AllowedDomains: []string{"example.com"},
		}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("localhost HTTP allowed", func(t *testing.T) {
		req := CreateOIDCProviderRequest{
			ProviderName:   "Test",
			IssuerURL:      "http://localhost:8080",
			ClientID:       "id",
			ClientSecret:   "secret",
			AllowedDomains: []string{"example.com"},
		}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("missing provider name", func(t *testing.T) {
		req := CreateOIDCProviderRequest{
			IssuerURL:      "https://idp.example.com",
			AllowedDomains: []string{"example.com"},
		}
		err := req.Validate(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "provider_name")
	})

	t.Run("missing issuer URL", func(t *testing.T) {
		req := CreateOIDCProviderRequest{
			ProviderName:   "Test",
			AllowedDomains: []string{"example.com"},
		}
		err := req.Validate(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issuer_url")
	})

	t.Run("non-HTTPS issuer URL", func(t *testing.T) {
		req := CreateOIDCProviderRequest{
			ProviderName:   "Test",
			IssuerURL:      "http://external.example.com",
			AllowedDomains: []string{"example.com"},
		}
		err := req.Validate(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTPS")
	})

	t.Run("client ID without secret", func(t *testing.T) {
		req := CreateOIDCProviderRequest{
			ProviderName:   "Test",
			IssuerURL:      "https://idp.example.com",
			ClientID:       "id",
			AllowedDomains: []string{"example.com"},
		}
		err := req.Validate(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_secret")
	})

	t.Run("missing allowed domains", func(t *testing.T) {
		req := CreateOIDCProviderRequest{
			ProviderName: "Test",
			IssuerURL:    "https://idp.example.com",
		}
		err := req.Validate(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "allowed domain")
	})
}

func TestCreateRoleRequest_Validate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid request", func(t *testing.T) {
		req := CreateRoleRequest{Name: "Admin", Description: "Admin role"}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("missing name", func(t *testing.T) {
		req := CreateRoleRequest{Description: "Admin role"}
		err := req.Validate(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name")
	})

	t.Run("missing description", func(t *testing.T) {
		req := CreateRoleRequest{Name: "Admin"}
		err := req.Validate(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "description")
	})
}

func TestSetRolePermissionsRequest_Validate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid request", func(t *testing.T) {
		req := SetRolePermissionsRequest{RoleID: uuid.New()}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("missing role ID", func(t *testing.T) {
		req := SetRolePermissionsRequest{}
		assert.Error(t, req.Validate(ctx))
	})
}

func TestRevokeSessionRequest_Validate(t *testing.T) {
	ctx := context.Background()

	t.Run("valid request", func(t *testing.T) {
		req := RevokeSessionRequest{SessionID: uuid.New()}
		assert.NoError(t, req.Validate(ctx))
	})

	t.Run("missing session ID", func(t *testing.T) {
		req := RevokeSessionRequest{}
		assert.Error(t, req.Validate(ctx))
	})
}
