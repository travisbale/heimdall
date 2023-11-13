package gin

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/travisbale/heimdall/internal/heimdall"
)

type authController interface {
	Login(context.Context, *heimdall.Credentials) (*heimdall.User, error)
}

type AuthHandler struct {
	controller authController
}

func NewAuthHandler(controller authController) *AuthHandler {
	return &AuthHandler{
		controller: controller,
	}
}

type Credentials struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type User struct {
	Email string `json:"email" binding:"required"`
}

func (h *AuthHandler) Login(ctx *gin.Context) {
	payload := &Credentials{}
	if err := ctx.ShouldBindJSON(payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	creds := &heimdall.Credentials{
		Email: payload.Email,
		Password: payload.Password,
	}

	user, err := h.controller.Login(ctx, creds)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, &User{
		Email: user.Email,
	})
}
