package http

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

const (
	refreshTokenCookie = "refresh_token"
	// TODO: Define this value once
	accessTokenExpiry = 15 * 60 // 15 minutes in seconds
)

// userService defines the interface for authentication operations
type userService interface {
	Login(ctx context.Context, email, password, ipAddress string) (*auth.User, error)
	GetScopes(ctx context.Context, userID uuid.UUID) ([]string, error)
}

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	userService   userService
	jwtService    jwtService
	secureCookies bool // Use Secure flag on cookies (HTTPS only)
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(userServiec userService, jwtIssuer jwtService, secureCookies bool) *AuthHandler {
	return &AuthHandler{
		userService:   userServiec,
		jwtService:    jwtIssuer,
		secureCookies: secureCookies,
	}
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req sdk.LoginRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	user, err := h.userService.Login(r.Context(), req.Email, req.Password, extractIPAddress(r))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			respondError(w, http.StatusUnauthorized, "Authentication failed", err)

		case errors.Is(err, auth.ErrEmailNotVerified):
			respondError(w, http.StatusForbidden, "Please verify your email address before logging in", err)

		case errors.Is(err, auth.ErrAccountIsInactive):
			respondError(w, http.StatusForbidden, "Your account is not active", err)

		case errors.Is(err, auth.ErrAccountLocked):
			respondError(w, http.StatusTooManyRequests, "Too many failed login attempts. Please try again later.", err)

		default:
			respondError(w, http.StatusInternalServerError, "Failed to authenticate user", err)
		}
		return
	}

	issueTokens(r.Context(), w, r, h.userService, h.jwtService, user.ID, user.TenantID, h.secureCookies)
}

// Logout handles user logout by clearing the refresh token cookie
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Construct cookie path using X-Forwarded-Prefix if available
	prefix := r.Header.Get("X-Forwarded-Prefix")
	cookiePath := prefix + sdk.RouteV1Refresh

	// Clear the refresh token cookie by setting MaxAge to -1
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    "",
		Path:     cookiePath,
		MaxAge:   -1, // Deletes the cookie
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	respondJSON(w, http.StatusOK, sdk.LogoutResponse{
		Message: "Logged out successfully",
	})
}

// RefreshToken handles token refresh using the refresh token from HTTP-only cookie
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Read refresh token from HTTP-only cookie
	cookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Missing refresh token", err)
		return
	}

	claims, err := h.jwtService.ValidateToken(cookie.Value)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid or expired refresh token", err)
		return
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to parse user ID", err)
		return
	}

	issueTokens(r.Context(), w, r, h.userService, h.jwtService, userID, claims.TenantID, h.secureCookies)
}

// extractIPAddress extracts the client IP address from the request
// Checks X-Forwarded-For header first (for proxied requests), then falls back to RemoteAddr
func extractIPAddress(r *http.Request) string {
	// Check X-Forwarded-For header (may contain multiple IPs if behind multiple proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (the original client)
		// X-Forwarded-For format: client, proxy1, proxy2
		if idx := len(xff); idx > 0 {
			for i, c := range xff {
				if c == ',' {
					idx = i
					break
				}
			}
			return xff[:idx]
		}
	}

	// Check X-Real-IP header (single IP)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr (format: "IP:port")
	// Strip port if present
	if idx := len(r.RemoteAddr); idx > 0 {
		for i := idx - 1; i >= 0; i-- {
			if r.RemoteAddr[i] == ':' {
				return r.RemoteAddr[:i]
			}
		}
	}

	return r.RemoteAddr
}
