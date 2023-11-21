package gin

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	tokenService tokenService
}

func NewAuthMiddleware(tokenService tokenService) *AuthMiddleware {
	return &AuthMiddleware{
		tokenService: tokenService,
	}
}

func (m *AuthMiddleware) requirePermission(requiredPermission string) gin.HandlerFunc {
	return m.requirePermissions([]string{requiredPermission})
}

func (m *AuthMiddleware) requirePermissions(requiredPermissions []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token, err := ctx.Cookie("access_token")
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Missing access_token cookie"})
			return
		}

		userPermissions, err := m.tokenService.ValidateToken(token, ctx.GetHeader("X-CSRF-TOKEN"))
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}

		for _, requiredPermission := range requiredPermissions {
			if !slices.Contains(userPermissions, requiredPermission) {
				errorMsg := fmt.Sprintf("Missing %s permission", requiredPermission)
				ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": errorMsg})
				return
			}
		}
	}
}
