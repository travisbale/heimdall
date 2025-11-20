package http

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

const refreshTokenCookie = "refresh_token"

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	userService   userService
	rbacService   rbacService
	jwtService    jwtService
	secureCookies bool // Secure flag prevents cookies from being sent over HTTP (only HTTPS)
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(config *Config) *AuthHandler {
	return &AuthHandler{
		userService:   config.UserService,
		rbacService:   config.RBACService,
		jwtService:    config.JWTService,
		secureCookies: config.SecureCookies(),
	}
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req sdk.LoginRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	user, err := h.userService.Login(r.Context(), req.Email, req.Password, identity.GetIPAddress(r.Context()))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Authentication failed"})

		case errors.Is(err, auth.ErrEmailNotVerified):
			respondJSON(w, http.StatusForbidden, sdk.ErrorResponse{Error: "Please verify your email address before logging in"})

		case errors.Is(err, auth.ErrAccountLocked):
			respondJSON(w, http.StatusTooManyRequests, sdk.ErrorResponse{Error: "Too many failed login attempts. Please try again later."})

		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to authenticate user"})
		}
		return
	}

	issueTokens(r.Context(), w, r, h.rbacService, h.jwtService, user.ID, user.TenantID, h.secureCookies)
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
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Missing refresh token"})
		return
	}

	claims, err := h.jwtService.ValidateToken(cookie.Value)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid or expired refresh token"})
		return
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to parse user ID"})
		return
	}

	issueTokens(r.Context(), w, r, h.rbacService, h.jwtService, userID, claims.TenantID, h.secureCookies)
}
