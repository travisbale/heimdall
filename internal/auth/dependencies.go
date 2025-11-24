package auth

import "context"

// hasher hashes and verifies passwords and codes
type hasher interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password, hash string) error
}

// logger provides structured logging capabilities
type logger interface {
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
	Debug(ctx context.Context, msg string, args ...any)
}
