package heimdall

import (
	"context"
)

type User struct {
	ID           int
	Email        string
	PasswordHash string
}

type userService interface {
	GetUser(ctx context.Context, email string) (*User, error)
}

type Permission struct {
	ID int
	Name        string
	Description string
}

type permissionService interface {
	GetPermissions(ctx context.Context, email string) ([]*Permission, error)
}

type passwordHasher interface {
	Hash(password string) (string, error)
	Verify(encodedHash string, password string) error
}

type logger interface {
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Error(msg string, ctx ...interface{})
}

type AuthController struct {
	userService       userService
	permissionService permissionService
	hasher            passwordHasher
	logger            logger
}

type AuthControllerConfig struct {
	UserService       userService
	PermissionService permissionService
	Hasher            passwordHasher
	Logger            logger
}

func NewAuthController(config *AuthControllerConfig) *AuthController {
	return &AuthController{
		userService:       config.UserService,
		permissionService: config.PermissionService,
		hasher:            config.Hasher,
		logger:            config.Logger,
	}
}

type Credentials struct {
	Email    string
	Password string
}

func (c *AuthController) Login(ctx context.Context, creds *Credentials) ([]string, error) {
	user, err := c.userService.GetUser(ctx, creds.Email)
	if err != nil {
		return nil, err
	}

	if err = c.hasher.Verify(user.PasswordHash, creds.Password); err != nil {
		return nil, err
	}

	permissions, err := c.permissionService.GetPermissions(ctx, user.Email)
	if err != nil {
		return nil, err
	}

	names := []string{}
	for _, permission := range permissions {
		names = append(names, permission.Name)
	}

	return names, nil
}
