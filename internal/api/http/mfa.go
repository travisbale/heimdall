package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
)

// Setup initiates MFA setup by generating secret, QR code, and backup codes
func (r *Router) setupMFA(w http.ResponseWriter, req *http.Request) {
	userID, ok := api.GetAuthenticatedActorID(w, req)
	if !ok {
		return
	}

	enrollment, err := r.MFAService.SetupMFA(req.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrMFAAlreadyEnabled):
			api.RespondError(w, http.StatusConflict, "MFA is already enabled", err)
		default:
			r.Logger.ErrorContext(req.Context(), "failed to setup MFA", "user_id", userID, "error", err)
			api.RespondError(w, http.StatusInternalServerError, "Failed to setup MFA", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusOK, &sdk.MFASetupResponse{
		Secret:      enrollment.Secret,
		QRCode:      enrollment.QRCode,
		BackupCodes: enrollment.BackupCodes,
	})
}

// Enable validates TOTP code and enables MFA
func (r *Router) enableMFA(w http.ResponseWriter, req *http.Request) {
	var body sdk.EnableMFARequest
	if !api.DecodeAndValidateJSON(w, req, &body) {
		return
	}

	userID, ok := api.GetAuthenticatedActorID(w, req)
	if !ok {
		return
	}

	err := r.MFAService.EnableMFA(req.Context(), userID, body.Code)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidMFACode):
			api.RespondError(w, http.StatusBadRequest, "Invalid MFA code", err)
		case errors.Is(err, iam.ErrMFAAlreadyEnabled):
			api.RespondError(w, http.StatusConflict, "MFA is already enabled", err)
		case errors.Is(err, iam.ErrMFANotEnabled):
			api.RespondError(w, http.StatusNotFound, "MFA setup not found. Please start MFA setup first.", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to enable MFA", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Disable disables MFA for a user (requires password and TOTP/backup code)
func (r *Router) disableMFA(w http.ResponseWriter, req *http.Request) {
	var body sdk.DisableMFARequest
	if !api.DecodeAndValidateJSON(w, req, &body) {
		return
	}

	userID, ok := api.GetAuthenticatedActorID(w, req)
	if !ok {
		return
	}

	err := r.MFAService.DisableMFA(req.Context(), userID, body.Password, body.Code)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidCredentials):
			api.RespondError(w, http.StatusUnauthorized, "Invalid password", err)
		case errors.Is(err, iam.ErrInvalidMFACode), errors.Is(err, iam.ErrInvalidBackupCode):
			api.RespondError(w, http.StatusBadRequest, "Invalid MFA code or backup code", err)
		case errors.Is(err, iam.ErrMFACodeAlreadyUsed):
			api.RespondError(w, http.StatusBadRequest, "This code has already been used", err)
		case errors.Is(err, iam.ErrMFANotEnabled):
			api.RespondError(w, http.StatusNotFound, "MFA is not enabled", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to disable MFA", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Status returns MFA status for the authenticated user
func (r *Router) mfaStatus(w http.ResponseWriter, req *http.Request) {
	userID, ok := api.GetAuthenticatedActorID(w, req)
	if !ok {
		return
	}

	status, err := r.MFAService.GetStatus(req.Context(), userID)
	if err != nil {
		if errors.Is(err, iam.ErrMFANotEnabled) {
			api.RespondError(w, http.StatusNotFound, "MFA is not enabled", err)
			return
		}
		api.RespondError(w, http.StatusInternalServerError, "Failed to get MFA status", err)
		return
	}

	api.RespondJSON(w, http.StatusOK, &sdk.MFAStatus{
		VerifiedAt:           status.VerifiedAt,
		BackupCodesRemaining: status.BackupCodesRemaining,
	})
}

// RegenerateCodes generates new backup codes (requires password)
func (r *Router) regenerateCodes(w http.ResponseWriter, req *http.Request) {
	var body sdk.RegenerateBackupCodesRequest
	if !api.DecodeAndValidateJSON(w, req, &body) {
		return
	}

	userID, ok := api.GetAuthenticatedActorID(w, req)
	if !ok {
		return
	}

	codes, err := r.MFAService.RegenerateBackupCodes(req.Context(), userID, body.Password)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidCredentials):
			api.RespondError(w, http.StatusUnauthorized, "Invalid password", err)
		case errors.Is(err, iam.ErrMFANotEnabled):
			api.RespondError(w, http.StatusNotFound, "MFA is not enabled", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to regenerate backup codes", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusOK, sdk.BackupCodesResponse{
		BackupCodes: codes,
	})
}

// MFALogin verifies MFA code during login and issues full access tokens
func (r *Router) mfaLogin(w http.ResponseWriter, req *http.Request) {
	var body sdk.VerifyMFACodeRequest
	if !api.DecodeAndValidateJSON(w, req, &body) {
		return
	}

	tokens, err := r.AuthService.AuthenticateWithMFA(req.Context(), body.ChallengeToken, body.Code, body.TrustDevice)
	if err != nil {
		r.Logger.WarnContext(req.Context(), events.MFAVerificationFailed, "error", err.Error())
		switch {
		case errors.Is(err, iam.ErrInvalidChallengeToken):
			api.RespondError(w, http.StatusUnauthorized, "Invalid or expired challenge token", err)
		case errors.Is(err, iam.ErrInvalidMFACode):
			api.RespondError(w, http.StatusUnauthorized, "Invalid MFA code", err)
		case errors.Is(err, iam.ErrMFACodeAlreadyUsed):
			api.RespondError(w, http.StatusBadRequest, "This code has already been used", err)
		case errors.Is(err, iam.ErrInvalidBackupCode):
			api.RespondError(w, http.StatusUnauthorized, "Invalid backup code", err)
		case errors.Is(err, iam.ErrBackupCodeAlreadyUsed):
			api.RespondError(w, http.StatusBadRequest, "This backup code has already been used", err)
		case errors.Is(err, iam.ErrMFANotEnabled):
			api.RespondError(w, http.StatusBadRequest, "MFA is not enabled", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to verify MFA", err)
		}
		return
	}

	r.Logger.InfoContext(req.Context(), events.MFAVerificationSuccess)

	// Set device trust cookie if a device token was generated
	if tokens.DeviceToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     deviceTrustCookie,
			Value:    tokens.DeviceToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.SecureCookies,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   30 * 24 * 60 * 60, // 30 days
		})
	}

	encodeSessionResponse(w, req, tokens, r.SecureCookies)
}

// RequiredSetup handles MFA setup when user's role requires MFA but they haven't set it up.
// This is an unauthenticated endpoint that validates the MFA setup token from login response.
func (r *Router) requiredSetup(w http.ResponseWriter, req *http.Request) {
	var body sdk.RequiredMFASetupRequest
	if !api.DecodeAndValidateJSON(w, req, &body) {
		return
	}

	enrollment, err := r.AuthService.SetupRequiredMFA(req.Context(), body.SetupToken)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidSetupToken):
			api.RespondError(w, http.StatusUnauthorized, "Invalid or expired setup token", err)
		case errors.Is(err, iam.ErrMFAAlreadyEnabled):
			api.RespondError(w, http.StatusConflict, "MFA is already enabled", err)
		default:
			r.Logger.ErrorContext(req.Context(), "failed to setup required MFA", "error", err)
			api.RespondError(w, http.StatusInternalServerError, "Failed to setup MFA", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusOK, &sdk.MFASetupResponse{
		Secret:      enrollment.Secret,
		QRCode:      enrollment.QRCode,
		BackupCodes: enrollment.BackupCodes,
	})
}

// RequiredEnable enables MFA after required setup and completes the login flow.
// This is an unauthenticated endpoint that validates the MFA setup token from login response.
func (r *Router) requiredEnable(w http.ResponseWriter, req *http.Request) {
	var body sdk.RequiredMFAEnableRequest
	if !api.DecodeAndValidateJSON(w, req, &body) {
		return
	}

	tokens, err := r.AuthService.EnableRequiredMFA(req.Context(), body.SetupToken, body.Code)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidSetupToken):
			api.RespondError(w, http.StatusUnauthorized, "Invalid or expired setup token", err)
		case errors.Is(err, iam.ErrInvalidMFACode):
			api.RespondError(w, http.StatusBadRequest, "Invalid MFA code", err)
		case errors.Is(err, iam.ErrMFAAlreadyEnabled):
			api.RespondError(w, http.StatusConflict, "MFA is already enabled", err)
		case errors.Is(err, iam.ErrMFANotEnabled):
			api.RespondError(w, http.StatusNotFound, "MFA setup not found. Please start MFA setup first.", err)
		default:
			r.Logger.ErrorContext(req.Context(), "failed to enable required MFA", "error", err)
			api.RespondError(w, http.StatusInternalServerError, "Failed to enable MFA", err)
		}
		return
	}

	encodeSessionResponse(w, req, tokens, r.SecureCookies)
}
