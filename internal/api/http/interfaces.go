package http

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

// userService defines the interface for user authentication and management operations
type userService interface {
	Login(ctx context.Context, email, password, ipAddress string) (*auth.User, error)

	Register(ctx context.Context, email string) (*auth.User, error)
	ConfirmRegistration(ctx context.Context, token string, password string) (*auth.User, error)

	InitiatePasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
}

// jwtService defines the interface for JWT token operations
type jwtService interface {
	IssueAccessToken(userID, tenantID uuid.UUID, scopes []sdk.Scope) (string, error)
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

// rbacService defines the interface for RBAC operations
type rbacService interface {
	ListPermissions(ctx context.Context) ([]*auth.Permission, error)
	GetUserScopes(ctx context.Context, userID uuid.UUID) ([]sdk.Scope, error)

	CreateRole(ctx context.Context, name, description string) (*auth.Role, error)
	GetRole(ctx context.Context, roleID uuid.UUID) (*auth.Role, error)
	ListRoles(ctx context.Context) ([]*auth.Role, error)
	UpdateRole(ctx context.Context, roleID uuid.UUID, name, description string) (*auth.Role, error)
	DeleteRole(ctx context.Context, roleID uuid.UUID) error

	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*auth.Permission, error)
	SetRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error

	SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*auth.Role, error)

	SetDirectPermissions(ctx context.Context, userID uuid.UUID, permissions []auth.DirectPermission) error
	GetDirectPermissions(ctx context.Context, userID uuid.UUID) ([]*auth.EffectivePermission, error)
}

// mfaService defines the interface for MFA operations
type mfaService interface {
	SetupMFA(ctx context.Context, userID uuid.UUID) (*auth.MFAEnrollment, error)
	EnableMFA(ctx context.Context, userID uuid.UUID, code string) error
	DisableMFA(ctx context.Context, userID uuid.UUID, password, code string) error
	GetStatus(ctx context.Context, userID uuid.UUID) (*auth.MFAStatus, error)
	RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, password string) ([]string, error)
	VerifyMFA(ctx context.Context, userID uuid.UUID, code string) error
}

type tokenService interface {
	IssueTokens(cxt context.Context, w http.ResponseWriter, r *http.Request, subject *Subject)
	RefreshToken(cxt context.Context, w http.ResponseWriter, r *http.Request)
	RevokeTokens(w http.ResponseWriter, r *http.Request)
}
