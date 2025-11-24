package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

// PasswordResetHandler handles password reset HTTP requests
type PasswordResetHandler struct {
	passwordService passwordService
}

// NewPasswordResetHandler creates a new PasswordResetHandler
func NewPasswordResetHandler(config *Config) *PasswordResetHandler {
	return &PasswordResetHandler{
		passwordService: config.PasswordService,
	}
}

// ForgotPassword handles password reset initiation
func (h *PasswordResetHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req sdk.ForgotPasswordRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	// Always return success regardless of outcome (prevent user enumeration)
	_ = h.passwordService.InitiatePasswordReset(r.Context(), req.Email)
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

	err := h.passwordService.ResetPassword(r.Context(), req.Token, req.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrPasswordResetTokenNotFound):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid or expired reset token"})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to reset password"})
		}
		return
	}

	respondJSON(w, http.StatusOK, sdk.ResetPasswordResponse{
		Message: "Password has been reset successfully. You can now log in with your new password.",
	})
}
