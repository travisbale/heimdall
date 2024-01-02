package heimdall

import (
	"context"
	"errors"
)

type passwordHasher interface {
	Hash(password string) (string, error)
	Verify(encodedHash string, password string) error
}

type lockoutService interface {
	CanLogin(userID int) error
	SaveLoginAttempt(userID int, successful bool) error
}

type AuthController struct {
	userService       userService
	permissionService permissionService
	lockoutService    lockoutService
	hasher            passwordHasher
	logger            logger
}

type AuthControllerConfig struct {
	UserService       userService
	PermissionService permissionService
	LockoutService    lockoutService
	Hasher            passwordHasher
	Logger            logger
}

func NewAuthController(config *AuthControllerConfig) *AuthController {
	return &AuthController{
		userService:       config.UserService,
		permissionService: config.PermissionService,
		lockoutService:    config.LockoutService,
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

	if err = c.lockoutService.CanLogin(user.ID); err != nil {
		return nil, err
	}

	if err = c.hasher.Verify(user.PasswordHash, creds.Password); err != nil {
		if errors.Is(ErrIncorrectPassword, err) {
			c.lockoutService.SaveLoginAttempt(user.ID, false)
		}

		return nil, err
	}

	c.lockoutService.SaveLoginAttempt(user.ID, true)

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
