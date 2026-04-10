package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
)

// Login handles user login
func (r *Router) login(w http.ResponseWriter, req *http.Request) {
	var body sdk.LoginRequest
	if !api.DecodeAndValidateJSON(w, req, &body) {
		return
	}

	// Read device trust cookie if present (for MFA bypass on trusted devices)
	var deviceToken string
	if cookie, err := req.Cookie(deviceTrustCookie); err == nil {
		deviceToken = cookie.Value
	}

	tokens, err := r.AuthService.AuthenticateWithPassword(req.Context(), body.Email, body.Password, deviceToken)
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

	encodeSessionResponse(w, req, tokens, r.SecureCookies)
}

// Logout handles user logout by revoking tokens
func (r *Router) logout(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie(refreshTokenCookie)
	if err != nil {
		api.RespondError(w, http.StatusUnauthorized, "Missing refresh token", err)
		return
	}

	if err := r.AuthService.Logout(req.Context(), cookie.Value); err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to revoke session", err)
		return
	}

	// Construct cookie path using X-Forwarded-Prefix if available
	prefix := req.Header.Get("X-Forwarded-Prefix")
	cookiePath := prefix + sdk.RouteV1Refresh

	// Clear the refresh token cookie by setting MaxAge to -1
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    "",
		Path:     cookiePath,
		MaxAge:   -1, // Deletes the cookie
		HttpOnly: true,
		Secure:   r.SecureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	api.RespondJSON(w, http.StatusOK, sdk.LogoutResponse{
		Message: "Logged out successfully",
	})
}

// RefreshToken handles token refresh using the refresh token from HTTP-only cookie
func (r *Router) refreshToken(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie(refreshTokenCookie)
	if err != nil {
		api.RespondError(w, http.StatusUnauthorized, "Missing refresh token", err)
		return
	}

	tokens, err := r.AuthService.RefreshSession(req.Context(), cookie.Value)
	if err != nil {
		api.RespondError(w, http.StatusUnauthorized, "Invalid or expired refresh token", err)
		return
	}

	encodeSessionResponse(w, req, tokens, r.SecureCookies)
}
