package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/travisbale/heimdall/internal/heimdall"
)

type LoginAttemptService struct {
	pool *pgxpool.Pool
}

func NewLoginAttemptService(pool * pgxpool.Pool) *LoginAttemptService {
	return &LoginAttemptService{
		pool: pool,
	}
}

func (s *LoginAttemptService) GetRecentAttempts(userID, count int) ([]*heimdall.LoginAttempt, error) {
	return []*heimdall.LoginAttempt{}, nil
}

func (s *LoginAttemptService) SaveAttempt(userID int, attempt *heimdall.LoginAttempt) error {
	return nil
}
