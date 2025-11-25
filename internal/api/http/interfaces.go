package http

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

// userService defines the interface for user registration and management operations
type userService interface {
	Register(ctx context.Context, email string) (*iam.User, error)
}

// passwordService defines the interface for password authentication operations
type passwordService interface {
	InitiatePasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error
}

// authService defines the interface for authentication orchestration
type authService interface {
	AuthenticateWithPassword(ctx context.Context, email, password string) (*iam.SessionTokens, error)
	AuthenticateWithOIDC(ctx context.Context, state, code string) (*iam.SessionTokens, error)
	AuthenticateWithMFA(ctx context.Context, challengeToken, code string) (*iam.SessionTokens, error)
	CompleteRegistration(ctx context.Context, token, password string) (*iam.SessionTokens, error)
	RefreshSession(ctx context.Context, refreshToken string) (*iam.SessionTokens, error)
}

// jwtService defines the interface for JWT token operations
type jwtService interface {
	IssueAccessToken(tenantID, userID uuid.UUID, scopes []sdk.Scope) (string, error)
	IssueMFAChallengeToken(userID, tenantID uuid.UUID) (string, error)
	IssueRefreshToken(tenantID, userID uuid.UUID) (string, error)
	ValidateToken(token string) (*jwt.Claims, error)
	ValidateMFAChallengeToken(token string) (*jwt.Claims, error)
	GetAccessTokenExpiration() time.Duration
	GetRefreshTokenExpiration() time.Duration
	GetMFAChallengeTokenExpiration() time.Duration
}

// oidcService defines the interface for OIDC/OAuth operations
type oidcService interface {
	StartOIDCLogin(ctx context.Context, providerType sdk.OIDCProviderType) (string, error)
	StartSSOLogin(ctx context.Context, email string) (string, error)

	CreateOIDCProvider(ctx context.Context, provider *iam.OIDCProviderConfig, accessToken string) (*iam.OIDCProviderConfig, error)
	GetOIDCProvider(ctx context.Context, providerID uuid.UUID) (*iam.OIDCProviderConfig, error)
	ListOIDCProviders(ctx context.Context) ([]*iam.OIDCProviderConfig, error)
	UpdateOIDCProvider(ctx context.Context, params *iam.UpdateOIDCProviderParams) (*iam.OIDCProviderConfig, error)
	DeleteOIDCProvider(ctx context.Context, providerID uuid.UUID) error
}

// rbacService defines the interface for RBAC operations
type rbacService interface {
	ListPermissions(ctx context.Context) ([]*iam.Permission, error)
	GetUserScopes(ctx context.Context, userID uuid.UUID) ([]sdk.Scope, error)

	CreateRole(ctx context.Context, role *iam.Role) (*iam.Role, error)
	GetRole(ctx context.Context, roleID uuid.UUID) (*iam.Role, error)
	ListRoles(ctx context.Context) ([]*iam.Role, error)
	UpdateRole(ctx context.Context, params iam.UpdateRoleParams) (*iam.Role, error)
	DeleteRole(ctx context.Context, roleID uuid.UUID) error

	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*iam.Permission, error)
	SetRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error

	SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*iam.Role, error)

	SetDirectPermissions(ctx context.Context, userID uuid.UUID, permissions []iam.DirectPermission) error
	GetDirectPermissions(ctx context.Context, userID uuid.UUID) ([]*iam.EffectivePermission, error)
}

// mfaService defines the interface for MFA operations
type mfaService interface {
	SetupMFA(ctx context.Context, userID uuid.UUID) (*iam.MFAEnrollment, error)
	EnableMFA(ctx context.Context, userID uuid.UUID, code string) error
	DisableMFA(ctx context.Context, userID uuid.UUID, password, code string) error
	GetStatus(ctx context.Context, userID uuid.UUID) (*iam.MFAStatus, error)
	RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, password string) ([]string, error)
}
