package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
)

const refreshTokenCookie = "refresh_token"
const deviceTrustCookie = "device_trust"

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	authService   authService
	secureCookies bool
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(config *Config) *AuthHandler {
	return &AuthHandler{
		authService:   config.AuthService,
		secureCookies: config.SecureCookies(),
	}
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req sdk.LoginRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	// Read device trust cookie if present (for MFA bypass on trusted devices)
	var deviceToken string
	if cookie, err := r.Cookie(deviceTrustCookie); err == nil {
		deviceToken = cookie.Value
	}

	tokens, err := h.authService.AuthenticateWithPassword(r.Context(), req.Email, req.Password, deviceToken)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidCredentials):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Authentication failed"})

		case errors.Is(err, iam.ErrEmailNotVerified):
			respondJSON(w, http.StatusForbidden, sdk.ErrorResponse{Error: "Please verify your email address before logging in"})

		case errors.Is(err, iam.ErrAccountLocked):
			respondJSON(w, http.StatusTooManyRequests, sdk.ErrorResponse{Error: "Too many failed login attempts. Please try again later."})

		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to authenticate user"})
		}
		return
	}

	encodeSessionResponse(w, r, tokens, h.secureCookies)
}

// Logout handles user logout by revoking tokens
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Missing refresh token"})
		return
	}

	if err := h.authService.Logout(r.Context(), cookie.Value); err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to revoke session"})
		return
	}

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
	cookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Missing refresh token"})
		return
	}

	tokens, err := h.authService.RefreshSession(r.Context(), cookie.Value)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid or expired refresh token"})
		return
	}

	encodeSessionResponse(w, r, tokens, h.secureCookies)
}
