package iam

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type userDB interface {
	CreateUser(ctx context.Context, user *User) (*User, error)
	GetUser(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, params *UpdateUserParams) (*User, error)
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
}

type tenantsDB interface {
	BootstrapTenant(ctx context.Context, email, firstName, lastName string, status UserStatus) (*Tenant, *User, error)
}

type tokenDB interface {
	CreateToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*UserToken, error)
	GetToken(ctx context.Context, token string) (*UserToken, error)
	DeleteToken(ctx context.Context, userID uuid.UUID) error
}
