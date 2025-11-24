package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

const refreshTokenCookie = "refresh_token"

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	passwordService passwordService
	tokenService    tokenService
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(config *Config) *AuthHandler {
	return &AuthHandler{
		passwordService: config.PasswordService,
		tokenService:    config.TokenService,
	}
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req sdk.LoginRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	user, err := h.passwordService.Authenticate(r.Context(), req.Email, req.Password)
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

	// Issue session tokens and check if user requires MFA
	h.tokenService.IssueTokens(r.Context(), w, r, user.TenantID, user.ID, true)
}

// Logout handles user logout by revoking tokens
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	h.tokenService.RevokeTokens(w, r)
}

// RefreshToken handles token refresh using the refresh token from HTTP-only cookie
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	h.tokenService.RefreshToken(r.Context(), w, r)
}
