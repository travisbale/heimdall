package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/travisbale/heimdall/internal/heimdall"
)

type UserService struct {
	pool *pgxpool.Pool
}

func NewUserService(ctx context.Context, connString string) (*UserService, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, err
	}

	return &UserService{
		pool: pool,
	}, nil
}

func (s *UserService) GetUser(ctx context.Context, email string) (*heimdall.User, error) {
	user := &heimdall.User{}
	err := s.pool.QueryRow(ctx, "SELECT email, password FROM users WHERE email=$1", email).Scan(&user.Email, &user.PasswordHash)
	if err != nil {
		return nil, err
	}

	return user, nil
}
