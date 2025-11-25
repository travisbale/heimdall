package iam

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// userDB provides database operations for users
type userDB interface {
	CreateUser(ctx context.Context, user *User) (*User, error)
	GetUser(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, params *UpdateUserParams) (*User, error)
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
}

// tenantsDB provides database operations for tenants
type tenantsDB interface {
	BootstrapTenant(ctx context.Context, email string, status UserStatus) (*Tenant, *User, error)
}

// tokenDB provides database operations for email verification and password reset tokens
type tokenDB interface {
	CreateToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*UserToken, error)
	GetToken(ctx context.Context, token string) (*UserToken, error)
	DeleteToken(ctx context.Context, userID uuid.UUID) error
}
