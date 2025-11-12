package jwt

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const claimsContextKey contextKey = "jwt_claims"

type validator interface {
	ValidateToken(token string) (*Claims, error)
}

// Middleware creates an HTTP middleware that validates JWT tokens
func Middleware(validator validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			// Expected format: "Bearer <token>"
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, `{"error":"invalid authorization header format"}`, http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]

			// Validate the token
			claims, err := validator.ValidateToken(tokenString)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// Parse user ID from claims
			userID, err := uuid.Parse(claims.Subject)
			if err != nil {
				http.Error(w, `{"error":"invalid user ID in token"}`, http.StatusUnauthorized)
				return
			}

			// Add claims and identity to request context
			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			ctx = identity.WithUser(ctx, userID, claims.TenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetJWTClaims extracts the full JWT claims from the request context
func GetJWTClaims(r *http.Request) (*Claims, error) {
	return getClaimsFromContext(r.Context())
}

// getClaimsFromContext retrieves JWT claims from the request context
func getClaimsFromContext(ctx context.Context) (*Claims, error) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	if !ok || claims == nil {
		return nil, errors.New("no claims found in context")
	}

	return claims, nil
}
