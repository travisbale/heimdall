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

type AuthController struct {
	userService userService
}

func NewAuthController(userService userService) *AuthController {
	return &AuthController{
		userService: userService,
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

	return user, nil
}
