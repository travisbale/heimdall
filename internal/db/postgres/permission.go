package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/travisbale/heimdall/internal/heimdall"
)

type PermissionService struct {
	pool *pgxpool.Pool
}

func NewPermissionService(pool *pgxpool.Pool) *PermissionService {
	return &PermissionService{
		pool: pool,
	}
}

func (s *PermissionService) GetPermissions(ctx context.Context, email string) ([]*heimdall.Permission, error) {
	query := `
		SELECT p.id, p.name, p.description
		FROM users AS u
			JOIN role_assignments AS ra ON u.id = ra.user_id
			JOIN permission_assignments AS pa ON pa.role_id = ra.role_id
			JOIN permissions AS p ON p.id = pa.permission_id
		WHERE email = $1
	`
	rows, err := s.pool.Query(ctx, query, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	permissions := []*heimdall.Permission{}

	for rows.Next() {
		permission := heimdall.Permission{}

		err := rows.Scan(&permission.ID, &permission.Name, &permission.Description)
		if err != nil {
			return nil, err
		}

		permissions = append(permissions, &permission)
	}

	return permissions, nil
}
