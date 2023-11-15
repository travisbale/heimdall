package postgres

import (
	"context"
	"errors"

	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/travisbale/heimdall/internal/heimdall"
)

type UserService struct {
	pool *pgxpool.Pool
}

func NewUserService(pool *pgxpool.Pool) (*UserService, error) {
	return &UserService{
		pool: pool,
	}, nil
}

func (s *UserService) GetUser(ctx context.Context, email string) (*heimdall.User, error) {
	user := &heimdall.User{}
	row := s.pool.QueryRow(ctx, "SELECT id, email, password FROM users WHERE email=$1", email)
	err := row.Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		if errors.Is(pgx.ErrNoRows, err) {
			return nil, heimdall.ErrUserNotFound
		}

		return nil, err
	}

	return user, nil
}
