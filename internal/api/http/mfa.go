package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
)

// MFAHandler handles MFA HTTP requests
type MFAHandler struct {
	mfaService    mfaService
	authService   authService
	secureCookies bool
	logger        logger
}

// NewMFAHandler creates a new MFAHandler
func NewMFAHandler(config *Config) *MFAHandler {
	return &MFAHandler{
		mfaService:    config.MFAService,
		authService:   config.AuthService,
		secureCookies: config.SecureCookies(),
		logger:        config.Logger,
	}
}

// Setup initiates MFA setup by generating secret, QR code, and backup codes
func (h *MFAHandler) Setup(w http.ResponseWriter, r *http.Request) {
	userID, err := identity.GetUser(r.Context())
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Unauthorized"})
		return
	}

	enrollment, err := h.mfaService.SetupMFA(r.Context(), userID)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrMFAAlreadyEnabled):
			respondJSON(w, http.StatusConflict, sdk.ErrorResponse{Error: "MFA is already enabled"})
		default:
			h.logger.Error(r.Context(), "failed to setup MFA", "user_id", userID, "error", err)
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to setup MFA"})
		}
		return
	}

	respondJSON(w, http.StatusOK, &sdk.MFASetupResponse{
		Secret:      enrollment.Secret,
		QRCode:      enrollment.QRCode,
		BackupCodes: enrollment.BackupCodes,
	})
}

// Enable validates TOTP code and enables MFA
func (h *MFAHandler) Enable(w http.ResponseWriter, r *http.Request) {
	var req sdk.EnableMFARequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	userID, err := identity.GetUser(r.Context())
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Unauthorized"})
		return
	}

	err = h.mfaService.EnableMFA(r.Context(), userID, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidMFACode):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid MFA code"})
		case errors.Is(err, iam.ErrMFAAlreadyEnabled):
			respondJSON(w, http.StatusConflict, sdk.ErrorResponse{Error: "MFA is already enabled"})
		case errors.Is(err, iam.ErrMFANotEnabled):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "MFA setup not found. Please start MFA setup first."})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to enable MFA"})
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Disable disables MFA for a user (requires password and TOTP/backup code)
func (h *MFAHandler) Disable(w http.ResponseWriter, r *http.Request) {
	var req sdk.DisableMFARequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	userID, err := identity.GetUser(r.Context())
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Unauthorized"})
		return
	}

	err = h.mfaService.DisableMFA(r.Context(), userID, req.Password, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidCredentials):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid password"})
		case errors.Is(err, iam.ErrInvalidMFACode), errors.Is(err, iam.ErrInvalidBackupCode):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid MFA code or backup code"})
		case errors.Is(err, iam.ErrMFACodeAlreadyUsed):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "This code has already been used"})
		case errors.Is(err, iam.ErrMFANotEnabled):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "MFA is not enabled"})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to disable MFA"})
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Status returns MFA status for the authenticated user
func (h *MFAHandler) Status(w http.ResponseWriter, r *http.Request) {
	userID, err := identity.GetUser(r.Context())
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Unauthorized"})
		return
	}

	status, err := h.mfaService.GetStatus(r.Context(), userID)
	if err != nil {
		if errors.Is(err, iam.ErrMFANotEnabled) {
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "MFA is not enabled"})
			return
		}
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to get MFA status"})
		return
	}

	respondJSON(w, http.StatusOK, &sdk.MFAStatus{
		VerifiedAt:           status.VerifiedAt,
		BackupCodesRemaining: status.BackupCodesRemaining,
	})
}

// RegenerateCodes generates new backup codes (requires password)
func (h *MFAHandler) RegenerateCodes(w http.ResponseWriter, r *http.Request) {
	var req sdk.RegenerateBackupCodesRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	userID, err := identity.GetUser(r.Context())
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Unauthorized"})
		return
	}

	codes, err := h.mfaService.RegenerateBackupCodes(r.Context(), userID, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidCredentials):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid password"})
		case errors.Is(err, iam.ErrMFANotEnabled):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "MFA is not enabled"})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to regenerate backup codes"})
		}
		return
	}

	respondJSON(w, http.StatusOK, sdk.BackupCodesResponse{
		BackupCodes: codes,
	})
}

// Login verifies MFA code during login and issues full access tokens
func (h *MFAHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req sdk.VerifyMFACodeRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	tokens, err := h.authService.AuthenticateWithMFA(r.Context(), req.ChallengeToken, req.Code)
	if err != nil {
		h.logger.Warn(r.Context(), events.MFAVerificationFailed, "error", err.Error())
		switch {
		case errors.Is(err, iam.ErrInvalidChallengeToken):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid or expired challenge token"})
		case errors.Is(err, iam.ErrInvalidMFACode):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid MFA code"})
		case errors.Is(err, iam.ErrMFACodeAlreadyUsed):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "This code has already been used"})
		case errors.Is(err, iam.ErrInvalidBackupCode):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid backup code"})
		case errors.Is(err, iam.ErrBackupCodeAlreadyUsed):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "This backup code has already been used"})
		case errors.Is(err, iam.ErrMFANotEnabled):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "MFA is not enabled"})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to verify MFA"})
		}
		return
	}

	h.logger.Info(r.Context(), events.MFAVerificationSuccess)

	encodeSessionResponse(w, r, tokens, h.secureCookies)
}

// RequiredSetup handles MFA setup when user's role requires MFA but they haven't set it up.
// This is an unauthenticated endpoint that validates the MFA setup token from login response.
func (h *MFAHandler) RequiredSetup(w http.ResponseWriter, r *http.Request) {
	var req sdk.RequiredMFASetupRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	enrollment, err := h.authService.SetupRequiredMFA(r.Context(), req.SetupToken)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidSetupToken):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid or expired setup token"})
		case errors.Is(err, iam.ErrMFAAlreadyEnabled):
			respondJSON(w, http.StatusConflict, sdk.ErrorResponse{Error: "MFA is already enabled"})
		default:
			h.logger.Error(r.Context(), "failed to setup required MFA", "error", err)
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to setup MFA"})
		}
		return
	}

	respondJSON(w, http.StatusOK, &sdk.MFASetupResponse{
		Secret:      enrollment.Secret,
		QRCode:      enrollment.QRCode,
		BackupCodes: enrollment.BackupCodes,
	})
}

// RequiredEnable enables MFA after required setup and completes the login flow.
// This is an unauthenticated endpoint that validates the MFA setup token from login response.
func (h *MFAHandler) RequiredEnable(w http.ResponseWriter, r *http.Request) {
	var req sdk.RequiredMFAEnableRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	tokens, err := h.authService.EnableRequiredMFA(r.Context(), req.SetupToken, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrInvalidSetupToken):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid or expired setup token"})
		case errors.Is(err, iam.ErrInvalidMFACode):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid MFA code"})
		case errors.Is(err, iam.ErrMFAAlreadyEnabled):
			respondJSON(w, http.StatusConflict, sdk.ErrorResponse{Error: "MFA is already enabled"})
		case errors.Is(err, iam.ErrMFANotEnabled):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "MFA setup not found. Please start MFA setup first."})
		default:
			h.logger.Error(r.Context(), "failed to enable required MFA", "error", err)
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to enable MFA"})
		}
		return
	}

	encodeSessionResponse(w, r, tokens, h.secureCookies)
}
