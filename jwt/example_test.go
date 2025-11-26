package jwt_test

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/travisbale/heimdall/jwt"
	"github.com/travisbale/heimdall/sdk"
)

// Example demonstrates the recommended struct-based API for JWT middleware
func Example_structBasedAPI() {
	// Initialize JWT service
	config := &jwt.Config{
		Issuer:                 "heimdall",
		PrivateKeyPath:         "/path/to/private.pem",
		PublicKeyPath:          "/path/to/public.pem",
		AccessTokenExpiration:  15 * 60,      // 15 minutes
		RefreshTokenExpiration: 24 * 60 * 60, // 24 hours
	}

	jwtService, err := jwt.NewService(config)
	if err != nil {
		panic(err)
	}

	// Create JWT middleware instance once
	jwtMiddleware := jwt.NewHTTPMiddleware(jwtService)

	// Create router
	r := chi.NewRouter()

	// Public endpoint - no authentication required
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// Protected endpoints
	r.Route("/api", func(r chi.Router) {
		// Endpoint requiring only authentication (no specific scopes)
		r.With(jwtMiddleware.Authenticate).Get("/profile", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"user":"..."}`))
		})

		// Endpoint requiring read:users permission
		r.With(jwtMiddleware.RequireScope(sdk.ScopeUserRead)).Get("/users", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"users":[]}`))
		})

		// Endpoint requiring both read:users and write:users permissions
		r.With(jwtMiddleware.RequireScope(sdk.ScopeUserRead, sdk.ScopeUserUpdate)).Post("/users", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":"123"}`))
		})

		// Endpoint requiring admin permission
		r.With(jwtMiddleware.RequireScope(sdk.Scope("admin:all"))).Delete("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		// Endpoint with multiple scope requirements
		r.With(jwtMiddleware.RequireScope(
			sdk.ScopeUserRead,
			sdk.Scope("read:permissions"),
			sdk.Scope("write:permissions"),
		)).Put("/users/{id}/permissions", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"success":true}`))
		})
	})

	// Start server
	fmt.Println("Server starting on :8080")
	http.ListenAndServe(":8080", r)
}

// Example showing how to retrieve claims within a handler
func Example_getClaims() {
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Get JWT claims from request context
		claims, err := jwt.GetJWTClaims(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Access user information from claims
		userID := claims.Subject
		tenantID := claims.TenantID
		scopes := claims.Scopes

		fmt.Fprintf(w, "User: %s, Tenant: %s, Scopes: %v", userID, tenantID, scopes)
	}

	// Use handler with middleware...
	_ = handler
}
