package gin

import (
	"github.com/gin-gonic/gin"
)

type tokenService interface {
}

type Config struct {
	TokenService tokenService
	AuthController authController
}

func NewRouter(config *Config) *gin.Engine {
	router := gin.Default()

	authHandler := NewAuthHandler(config.TokenService, config.AuthController)
	router.POST("/login", authHandler.Login)

	return router
}
