package gin

import (
	"context"
	"errors"
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

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Email string `json:"email" binding:"required"`
}

func (h *AuthHandler) Login(ctx *gin.Context) {
	payload := &LoginRequest{}
	if err := ctx.ShouldBindJSON(payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	creds := &heimdall.Credentials{
		Email:    payload.Email,
		Password: payload.Password,
	}

	user, err := h.controller.Login(ctx, creds)
	if err != nil {
		if errors.Is(heimdall.ErrIncorrectPassword, err) || errors.Is(heimdall.ErrUserNotFound, err) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect username or password"})
			return
		}

		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, &LoginResponse{
		Email: user.Email,
	})
}
