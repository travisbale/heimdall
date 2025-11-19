package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

// PasswordResetHandler handles password reset HTTP requests
type PasswordResetHandler struct {
	userService userService
}

// NewPasswordResetHandler creates a new PasswordResetHandler
func NewPasswordResetHandler(config *Config) *PasswordResetHandler {
	return &PasswordResetHandler{
		userService: config.UserService,
	}
}

// ForgotPassword handles password reset initiation
func (h *PasswordResetHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req sdk.ForgotPasswordRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	// Always return success regardless of outcome (prevent user enumeration)
	_ = h.userService.InitiatePasswordReset(r.Context(), req.Email)
	respondJSON(w, http.StatusOK, sdk.ForgotPasswordResponse{
		Message: "If an account exists with this email, a password reset link has been sent.",
	})
}

// ResetPassword handles password reset completion
func (h *PasswordResetHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req sdk.ResetPasswordRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	err := h.userService.ResetPassword(r.Context(), req.Token, req.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrPasswordResetTokenNotFound):
			respondError(w, http.StatusBadRequest, "Invalid or expired reset token", err)
		default:
			respondError(w, http.StatusInternalServerError, "Failed to reset password", err)
		}
		return
	}

	respondJSON(w, http.StatusOK, sdk.ResetPasswordResponse{
		Message: "Password has been reset successfully. You can now log in with your new password.",
	})
}
