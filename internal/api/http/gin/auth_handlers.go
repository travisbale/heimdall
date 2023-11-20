package gin

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/travisbale/heimdall/internal/heimdall"
)

type tokenService interface {
	CreateAccessToken(subject string, permissions []string) (string, string, error)
	CreateRefreshToken(subject string) (string, string, error)
}

type authController interface {
	Login(context.Context, *heimdall.Credentials) ([]string, error)
}

type AuthHandler struct {
	tokenService tokenService
	controller   authController
}

func NewAuthHandler(tokenService tokenService, controller authController) *AuthHandler {
	return &AuthHandler{
		tokenService: tokenService,
		controller:   controller,
	}
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Permissions []string `json:"permissions" binding:"required"`
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

	permissions, err := h.controller.Login(ctx, creds)
	if err != nil {
		if errors.Is(heimdall.ErrIncorrectPassword, err) || errors.Is(heimdall.ErrUserNotFound, err) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Incorrect username or password"})
			return
		}

		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	accessToken, accessCSRF, err := h.tokenService.CreateAccessToken(creds.Email, permissions)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	refreshToken, refreshCSRF, err := h.tokenService.CreateRefreshToken(creds.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	setCookies(ctx, accessToken, accessCSRF, refreshToken, refreshCSRF)

	ctx.JSON(http.StatusOK, &LoginResponse{
		Permissions: permissions,
	})
}

func (h *AuthHandler) Logout(ctx *gin.Context) {
	setCookies(ctx, "", "", "", "")
}

func setCookies(ctx *gin.Context, accessToken, accessCSRF, refreshToken, refreshCSRF string) {
	jwtCookieDomain := os.Getenv("JWT_COOKIE_DOMAIN")
	jwtSecureCookie := strings.ToLower(os.Getenv("JWT_SECURE_COOKIE"))

	ctx.SetCookie("access_token", accessToken, 0, "/", jwtCookieDomain, jwtSecureCookie == "true", true)
	ctx.SetCookie("refresh_token", refreshToken, 0, "/refresh", jwtCookieDomain, jwtSecureCookie == "true", true)
	ctx.SetCookie("csrf_access_token", accessCSRF, 0, "/", jwtCookieDomain, jwtSecureCookie == "true", false)
	ctx.SetCookie("csrf_refresh_token", refreshCSRF, 0, "/", jwtCookieDomain, jwtSecureCookie == "true", false)
}
