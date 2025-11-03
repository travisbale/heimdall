package http

import (
	"context"
	"net/http"

	"github.com/travisbale/heimdall/sdk"
)

type passwordResetService interface {
	InitiatePasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
}

// PasswordResetHandler handles password reset HTTP requests
type PasswordResetHandler struct {
	passwordResetService passwordResetService
}

// NewPasswordResetHandler creates a new PasswordResetHandler
func NewPasswordResetHandler(passwordResetService passwordResetService) *PasswordResetHandler {
	return &PasswordResetHandler{
		passwordResetService: passwordResetService,
	}
}

// ForgotPassword handles password reset initiation
func (h *PasswordResetHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req sdk.ForgotPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	err := h.passwordResetService.InitiatePasswordReset(r.Context(), req.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to process password reset request", err)
		return
	}

	// Always return success to prevent user enumeration
	respondJSON(w, http.StatusOK, sdk.ForgotPasswordResponse{
		Message: "If an account exists with this email, a password reset link has been sent.",
	})
}

// ResetPassword handles password reset completion
func (h *PasswordResetHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req sdk.ResetPasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	err := h.passwordResetService.ResetPassword(r.Context(), req.Token, req.NewPassword)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid or expired reset token", err)
		return
	}

	respondJSON(w, http.StatusOK, sdk.ResetPasswordResponse{
		Message: "Password has been reset successfully. You can now log in with your new password.",
	})
}
