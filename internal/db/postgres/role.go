package postgres

import (
	"context"

	// pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/travisbale/heimdall/internal/heimdall"
)

type RoleService struct {
	pool *pgxpool.Pool
}

func NewRoleService(pool *pgxpool.Pool) *RoleService {
	return &RoleService{
		pool: pool,
	}
}

func (s *RoleService) GetRoles(ctx context.Context) ([]*heimdall.Role, error) {
	query := `SELECT id, name, description FROM roles`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := []*heimdall.Role{}

	for rows.Next() {
		role := heimdall.Role{}

		err := rows.Scan(&role.ID, &role.Name, &role.Description)
		if err != nil {
			return nil, err
		}

		roles = append(roles, &role)
	}

	return roles, nil
}

func (s *RoleService) AssignRoleToUser(ctx context.Context, userId int, role *heimdall.Role) error {
	return nil
}
