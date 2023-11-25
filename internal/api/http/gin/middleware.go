package gin

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/travisbale/heimdall/pkg/jwt"
)

type jwtValidator interface {
	ValidateToken(tokenString, csrf string) (*jwt.Claims, error)
}

type AuthMiddleware struct {
	jwtValidator jwtValidator
}

func NewAuthMiddleware(jwtValidator jwtValidator) *AuthMiddleware {
	return &AuthMiddleware{
		jwtValidator: jwtValidator,
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

		claims, err := m.jwtValidator.ValidateToken(token, ctx.GetHeader("X-CSRF-TOKEN"))
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}

		for _, requiredPermission := range requiredPermissions {
			if err := claims.HasPermission(requiredPermission); err != nil {
				errorMsg := fmt.Sprintf("Missing %s permission", requiredPermission)
				ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": errorMsg})
				return
			}
		}
	}
}
