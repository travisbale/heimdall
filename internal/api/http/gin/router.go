package gin

import (
	"github.com/gin-gonic/gin"
)

type Config struct {
	TokenService   tokenService
	AuthController authController
	RoleController roleController
}

func NewRouter(config *Config) *gin.Engine {
	router := gin.Default()

	authHandler := NewAuthHandler(config.TokenService, config.AuthController)
	router.POST("/login", authHandler.Login)
	router.DELETE("/logout", authHandler.Logout)

	roleHandler := NewRoleHandler(config.RoleController)
	router.GET("/v1/roles", roleHandler.GetRoles)

	return router
}
