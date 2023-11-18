package heimdall

import "context"

type User struct {
	ID           int
	Email        string
	PasswordHash string
}

type userService interface {
	GetUser(ctx context.Context, email string) (*User, error)
}

type Permission struct {
	ID          int
	Name        string
	Description string
}

type permissionService interface {
	GetPermissions(ctx context.Context, email string) ([]*Permission, error)
}
