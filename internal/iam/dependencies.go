package iam

import (
	"context"

	"github.com/google/uuid"
)

// hasher hashes and verifies passwords and codes
type hasher interface {
	Hash(input string) (string, error)
	Verify(input, hash string) error
}

// logger provides structured logging capabilities (matches *ulog.Logger)
type logger interface {
	InfoContext(ctx context.Context, msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
	DebugContext(ctx context.Context, msg string, args ...any)
	AuditContext(ctx context.Context, msg string, args ...any)
}

// rbacService provides role-based access control operations
type rbacService interface {
	GetUserScopes(ctx context.Context, userID uuid.UUID) ([]Scope, error)
	SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
	UserRolesRequireMFA(ctx context.Context, userID uuid.UUID) (bool, error)
}
