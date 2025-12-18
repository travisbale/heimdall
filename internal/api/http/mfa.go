package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
)

// MFAHandler handles MFA HTTP requests
type MFAHandler struct {
	MFAService    mfaService
	AuthService   authService
	SecureCookies bool
	Logger        logger
}

// Setup initiates MFA setup by generating secret, QR code, and backup codes
func (h *MFAHandler) Setup(w http.ResponseWriter, r *http.Request) {
	userID, ok := api.GetAuthenticatedActorID(w, r)
	if !ok {
		return
	}

	enrollment, err := h.MFAService.SetupMFA(r.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrMFAAlreadyEnabled):
			api.RespondError(w, http.StatusConflict, "MFA is already enabled", err)
		default:
			h.Logger.ErrorContext(r.Context(), "failed to setup MFA", "user_id", userID, "error", err)
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
func (h *MFAHandler) Enable(w http.ResponseWriter, r *http.Request) {
	var req sdk.EnableMFARequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	userID, ok := api.GetAuthenticatedActorID(w, r)
	if !ok {
		return
	}

	err := h.MFAService.EnableMFA(r.Context(), userID, req.Code)
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
func (h *MFAHandler) Disable(w http.ResponseWriter, r *http.Request) {
	var req sdk.DisableMFARequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	userID, ok := api.GetAuthenticatedActorID(w, r)
	if !ok {
		return
	}

	err := h.MFAService.DisableMFA(r.Context(), userID, req.Password, req.Code)
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
func (h *MFAHandler) Status(w http.ResponseWriter, r *http.Request) {
	userID, ok := api.GetAuthenticatedActorID(w, r)
	if !ok {
		return
	}

	status, err := h.MFAService.GetStatus(r.Context(), userID)
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
func (h *MFAHandler) RegenerateCodes(w http.ResponseWriter, r *http.Request) {
	var req sdk.RegenerateBackupCodesRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	userID, ok := api.GetAuthenticatedActorID(w, r)
	if !ok {
		return
	}

	codes, err := h.MFAService.RegenerateBackupCodes(r.Context(), userID, req.Password)
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

// Login verifies MFA code during login and issues full access tokens
func (h *MFAHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req sdk.VerifyMFACodeRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	tokens, err := h.AuthService.AuthenticateWithMFA(r.Context(), req.ChallengeToken, req.Code, req.TrustDevice)
	if err != nil {
		h.Logger.WarnContext(r.Context(), events.MFAVerificationFailed, "error", err.Error())
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

	h.Logger.InfoContext(r.Context(), events.MFAVerificationSuccess)

	// Set device trust cookie if a device token was generated
	if tokens.DeviceToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     deviceTrustCookie,
			Value:    tokens.DeviceToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   h.SecureCookies,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   30 * 24 * 60 * 60, // 30 days
		})
	}

	encodeSessionResponse(w, r, tokens, h.SecureCookies)
}

// RequiredSetup handles MFA setup when user's role requires MFA but they haven't set it up.
// This is an unauthenticated endpoint that validates the MFA setup token from login response.
func (h *MFAHandler) RequiredSetup(w http.ResponseWriter, r *http.Request) {
	var req sdk.RequiredMFASetupRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	enrollment, err := h.AuthService.SetupRequiredMFA(r.Context(), req.SetupToken)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidSetupToken):
			api.RespondError(w, http.StatusUnauthorized, "Invalid or expired setup token", err)
		case errors.Is(err, iam.ErrMFAAlreadyEnabled):
			api.RespondError(w, http.StatusConflict, "MFA is already enabled", err)
		default:
			h.Logger.ErrorContext(r.Context(), "failed to setup required MFA", "error", err)
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
func (h *MFAHandler) RequiredEnable(w http.ResponseWriter, r *http.Request) {
	var req sdk.RequiredMFAEnableRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	tokens, err := h.AuthService.EnableRequiredMFA(r.Context(), req.SetupToken, req.Code)
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
			h.Logger.ErrorContext(r.Context(), "failed to enable required MFA", "error", err)
			api.RespondError(w, http.StatusInternalServerError, "Failed to enable MFA", err)
		}
		return
	}

	encodeSessionResponse(w, r, tokens, h.SecureCookies)
}
