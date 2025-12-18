package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
)

// PasswordResetHandler handles password reset HTTP requests
type PasswordResetHandler struct {
	PasswordService passwordService
}

// ForgotPassword handles password reset initiation
func (h *PasswordResetHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req sdk.ForgotPasswordRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	// Always return success regardless of outcome (prevent user enumeration)
	_ = h.PasswordService.InitiatePasswordReset(r.Context(), req.Email)
	api.RespondJSON(w, http.StatusOK, sdk.ForgotPasswordResponse{
		Message: "If an account exists with this email, a password reset link has been sent.",
	})
}

// ResetPassword handles password reset completion
func (h *PasswordResetHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req sdk.ResetPasswordRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	err := h.PasswordService.ResetPassword(r.Context(), req.Token, req.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrPasswordResetTokenNotFound):
			api.RespondError(w, http.StatusBadRequest, "Invalid or expired reset token", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to reset password", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusOK, sdk.ResetPasswordResponse{
		Message: "Password has been reset successfully. You can now log in with your new password.",
	})
}
