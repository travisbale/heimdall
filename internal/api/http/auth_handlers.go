package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

const refreshTokenCookie = "refresh_token"

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	userService  userService
	mfaService   mfaService
	tokenService tokenService
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(config *Config) *AuthHandler {
	return &AuthHandler{
		userService:  config.UserService,
		mfaService:   config.MFAService,
		tokenService: config.TokenService,
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

	// Add tenant context for MFA status check (RLS requirement)
	ctx := identity.WithTenant(r.Context(), user.TenantID)
	mfaStatus, err := h.mfaService.GetStatus(ctx, user.ID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to get MFA status"})
		return
	}

	h.tokenService.IssueTokens(r.Context(), w, r, &Subject{
		UserID:      user.ID,
		TenantID:    user.TenantID,
		MFARequired: mfaStatus.VerifiedAt != nil,
	})
}

// Logout handles user logout by revoking tokens
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	h.tokenService.RevokeTokens(w, r)
}

// RefreshToken handles token refresh using the refresh token from HTTP-only cookie
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	h.tokenService.RefreshToken(r.Context(), w, r)
}
