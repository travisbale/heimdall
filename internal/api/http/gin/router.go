package gin

import (
	"github.com/gin-gonic/gin"
)

type Controllers struct {
	AuthController authController
}

func NewRouter(controllers *Controllers) *gin.Engine {
	router := gin.Default()

	authHandler := NewAuthHandler(controllers.AuthController)
	router.POST("/login", authHandler.Login)

	return router
}
