package heimdall

import "context"

type Role struct {
	ID          int
	Name        string
	Description string
}

type roleService interface {
	GetRoles(ctx context.Context) ([]*Role, error)
}

type RoleController struct {
	roleService roleService
}

func NewRoleController(roleService roleService) *RoleController {
	return &RoleController{
		roleService: roleService,
	}
}

func (c *RoleController) GetRoles(ctx context.Context) ([]*Role, error) {
	roles, err := c.roleService.GetRoles(ctx)
	if err != nil {
		return nil, err
	}

	return roles, nil
}
