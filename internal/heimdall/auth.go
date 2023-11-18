package heimdall

import (
	"context"
)

type passwordHasher interface {
	Hash(password string) (string, error)
	Verify(encodedHash string, password string) error
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
