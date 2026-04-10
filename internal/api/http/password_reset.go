package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
)

// ForgotPassword handles password reset initiation
func (r *Router) forgotPassword(w http.ResponseWriter, req *http.Request) {
	var body sdk.ForgotPasswordRequest
	if !r.decodeAndValidateJSON(w, req, &body) {
		return
	}

	// Always return success regardless of outcome (prevent user enumeration)
	_ = r.PasswordService.InitiatePasswordReset(req.Context(), body.Email)
	r.writeJSON(w, http.StatusOK, sdk.ForgotPasswordResponse{
		Message: "If an account exists with this email, a password reset link has been sent.",
	})
}

// ResetPassword handles password reset completion
func (r *Router) resetPassword(w http.ResponseWriter, req *http.Request) {
	var body sdk.ResetPasswordRequest
	if !r.decodeAndValidateJSON(w, req, &body) {
		return
	}

	err := r.PasswordService.ResetPassword(req.Context(), body.Token, body.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrPasswordResetTokenNotFound):
			r.writeError(req.Context(), w, http.StatusBadRequest, "Invalid or expired reset token", err)
		default:
			r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to reset password", err)
		}
		return
	}

	r.writeJSON(w, http.StatusOK, sdk.ResetPasswordResponse{
		Message: "Password has been reset successfully. You can now log in with your new password.",
	})
}
