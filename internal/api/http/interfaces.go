package http

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

// userService defines the interface for user authentication and management operations
type userService interface {
	Login(ctx context.Context, email, password, ipAddress string) (*auth.User, error)
	GetScopes(ctx context.Context, userID uuid.UUID) ([]string, error)

	Register(ctx context.Context, email string) (*auth.User, error)
	ConfirmRegistration(ctx context.Context, token string, password string) (*auth.User, error)

	InitiatePasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
}

// jwtService defines the interface for JWT token operations
type jwtService interface {
	IssueAccessToken(userID, tenantID uuid.UUID, scopes []string) (string, error)
	IssueRefreshToken(userID, tenantID uuid.UUID) (string, error)
	ValidateToken(token string) (*jwt.Claims, error)
	GetAccessTokenExpiration() time.Duration
	GetRefreshTokenExpiration() time.Duration
}

// oidcService defines the interface for OIDC/OAuth operations
type oidcService interface {
	StartOIDCLogin(ctx context.Context, providerType sdk.OIDCProviderType) (string, error)
	StartSSOLogin(ctx context.Context, email string) (string, error)
	HandleOIDCCallback(ctx context.Context, state, code string) (*auth.User, *auth.OIDCLink, error)

	CreateOIDCProvider(ctx context.Context, provider *auth.OIDCProviderConfig, accessToken string) (*auth.OIDCProviderConfig, error)
	GetOIDCProvider(ctx context.Context, providerID uuid.UUID) (*auth.OIDCProviderConfig, error)
	ListOIDCProviders(ctx context.Context) ([]*auth.OIDCProviderConfig, error)
	UpdateOIDCProvider(ctx context.Context, params *auth.UpdateOIDCProviderParams) (*auth.OIDCProviderConfig, error)
	DeleteOIDCProvider(ctx context.Context, providerID uuid.UUID) error
}
