package auth

import (
	"context"
)

type logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

type oidcService interface {
	IsPasswordRegistrationAllowed(ctx context.Context, email string) error
}
