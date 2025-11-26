package iam

import (
	"context"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// hasher hashes and verifies passwords and codes
type hasher interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password, hash string) error
}

// logger provides structured logging capabilities (matches *slog.Logger)
type logger interface {
	InfoContext(ctx context.Context, msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
	DebugContext(ctx context.Context, msg string, args ...any)
}

// rbacService provides role-based access control operations
type rbacService interface {
	GetUserScopes(ctx context.Context, userID uuid.UUID) ([]sdk.Scope, error)
	SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
	UserRolesRequireMFA(ctx context.Context, userID uuid.UUID) (bool, error)
}
