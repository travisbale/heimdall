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

// rbacService provides role-based access control operations
type rbacService interface {
	GetUserScopes(ctx context.Context, userID uuid.UUID) ([]Scope, error)
	SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
	UserRolesRequireMFA(ctx context.Context, userID uuid.UUID) (bool, error)
}
