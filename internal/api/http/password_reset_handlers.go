package http

import (
	"net/http"

	"github.com/travisbale/heimdall/sdk"
)

// PasswordResetHandler handles password reset HTTP requests
type PasswordResetHandler struct {
	userService userService
}

// NewPasswordResetHandler creates a new PasswordResetHandler
func NewPasswordResetHandler(userService userService) *PasswordResetHandler {
	return &PasswordResetHandler{
		userService: userService,
	}
}

// ForgotPassword handles password reset initiation
func (h *PasswordResetHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req sdk.ForgotPasswordRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	err := h.userService.InitiatePasswordReset(r.Context(), req.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to process password reset request", err)
		return
	}

	// Always return success to prevent user enumeration attacks
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
		respondError(w, http.StatusBadRequest, "Invalid or expired reset token", err)
		return
	}

	respondJSON(w, http.StatusOK, sdk.ResetPasswordResponse{
		Message: "Password has been reset successfully. You can now log in with your new password.",
	})
}
