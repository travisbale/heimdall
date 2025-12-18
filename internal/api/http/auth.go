package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
)

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	AuthService   authService
	SecureCookies bool
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req sdk.LoginRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	// Read device trust cookie if present (for MFA bypass on trusted devices)
	var deviceToken string
	if cookie, err := r.Cookie(deviceTrustCookie); err == nil {
		deviceToken = cookie.Value
	}

	tokens, err := h.AuthService.AuthenticateWithPassword(r.Context(), req.Email, req.Password, deviceToken)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidCredentials):
			api.RespondError(w, http.StatusUnauthorized, "Authentication failed", err)
		case errors.Is(err, iam.ErrEmailNotVerified):
			api.RespondError(w, http.StatusForbidden, "Please verify your email address before logging in", err)
		case errors.Is(err, iam.ErrAccountLocked):
			api.RespondError(w, http.StatusTooManyRequests, "Too many failed login attempts. Please try again later.", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to authenticate user", err)
		}
		return
	}

	encodeSessionResponse(w, r, tokens, h.SecureCookies)
}

// Logout handles user logout by revoking tokens
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		api.RespondError(w, http.StatusUnauthorized, "Missing refresh token", err)
		return
	}

	if err := h.AuthService.Logout(r.Context(), cookie.Value); err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to revoke session", err)
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
		Secure:   h.SecureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	api.RespondJSON(w, http.StatusOK, sdk.LogoutResponse{
		Message: "Logged out successfully",
	})
}

// RefreshToken handles token refresh using the refresh token from HTTP-only cookie
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		api.RespondError(w, http.StatusUnauthorized, "Missing refresh token", err)
		return
	}

	tokens, err := h.AuthService.RefreshSession(r.Context(), cookie.Value)
	if err != nil {
		api.RespondError(w, http.StatusUnauthorized, "Invalid or expired refresh token", err)
		return
	}

	encodeSessionResponse(w, r, tokens, h.SecureCookies)
}
