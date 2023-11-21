package gin

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/travisbale/heimdall/internal/heimdall"
)

type roleController interface {
	GetRoles(ctx context.Context) ([]*heimdall.Role, error)
}

type RoleHandler struct {
	controller roleController
}

func NewRoleHandler(controller roleController) *RoleHandler {
	return &RoleHandler{
		controller: controller,
	}
}

type GetRoleResponse struct {
	ID          int    `json:"id" binding:"required"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description" binding:"required"`
}

type GetRolesResponse struct {
	Roles []*GetRoleResponse `json:"roles" binding:"required"`
}

func (h *RoleHandler) GetRoles(ctx *gin.Context) {
	roles, err := h.controller.GetRoles(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := &GetRolesResponse{Roles: make([]*GetRoleResponse, len(roles))}
	for i, role := range roles {
		response.Roles[i] = &GetRoleResponse{
			ID: role.ID,
			Name: role.Name,
			Description: role.Description,
		}
	}

	ctx.JSON(http.StatusOK, response)
}
