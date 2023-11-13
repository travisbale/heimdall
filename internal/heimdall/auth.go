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
	userService userService
	hasher      passwordHasher
	logger      logger
}

func NewAuthController(userService userService, hasher passwordHasher, logger logger) *AuthController {
	return &AuthController{
		userService: userService,
		hasher:      hasher,
		logger:      logger,
	}
}

type Credentials struct {
	Email    string
	Password string
}

func (c *AuthController) Login(ctx context.Context, creds *Credentials) (*User, error) {
	user, err := c.userService.GetUser(ctx, creds.Email)
	if err != nil {
		return nil, err
	}

	if err = c.hasher.Verify(user.PasswordHash, creds.Password); err != nil {
		return nil, err
	}

	return user, nil
}
