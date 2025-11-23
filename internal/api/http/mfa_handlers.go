package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/events"
	"github.com/travisbale/heimdall/sdk"
)

// MFAHandler handles MFA HTTP requests
type MFAHandler struct {
	mfaService   mfaService
	tokenService tokenService
	logger       logger
}

// NewMFAHandler creates a new MFAHandler
func NewMFAHandler(config *Config) *MFAHandler {
	return &MFAHandler{
		mfaService:   config.MFAService,
		tokenService: config.TokenService,
		logger:       config.Logger,
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
		case errors.Is(err, auth.ErrMFAAlreadyEnabled):
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
		case errors.Is(err, auth.ErrInvalidMFACode):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid MFA code"})
		case errors.Is(err, auth.ErrMFAAlreadyEnabled):
			respondJSON(w, http.StatusConflict, sdk.ErrorResponse{Error: "MFA is already enabled"})
		case errors.Is(err, auth.ErrMFANotEnabled):
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
		case errors.Is(err, auth.ErrInvalidCredentials):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid password"})
		case errors.Is(err, auth.ErrInvalidMFACode), errors.Is(err, auth.ErrInvalidBackupCode):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid MFA code or backup code"})
		case errors.Is(err, auth.ErrMFACodeAlreadyUsed):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "This code has already been used"})
		case errors.Is(err, auth.ErrMFANotEnabled):
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
		case errors.Is(err, auth.ErrInvalidCredentials):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid password"})
		case errors.Is(err, auth.ErrMFANotEnabled):
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
	var req sdk.VerifyMFALoginRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	userID, tenantID, err := identity.GetUserAndTenant(r.Context())
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Unauthorized"})
		return
	}

	err = h.mfaService.VerifyMFA(r.Context(), userID, req.Code)
	if err != nil {
		h.logger.Warn(r.Context(), events.MFAVerificationFailed, "user_id", userID, "error", err.Error())
		switch {
		case errors.Is(err, auth.ErrInvalidMFACode):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid MFA code"})
		case errors.Is(err, auth.ErrMFACodeAlreadyUsed):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "This code has already been used"})
		case errors.Is(err, auth.ErrInvalidBackupCode):
			respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid backup code"})
		case errors.Is(err, auth.ErrBackupCodeAlreadyUsed):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "This backup code has already been used"})
		case errors.Is(err, auth.ErrMFANotEnabled):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "MFA is not enabled"})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to verify MFA"})
		}
		return
	}

	h.logger.Info(r.Context(), events.MFAVerificationSuccess, "user_id", userID)

	h.tokenService.IssueTokens(r.Context(), w, r, &Subject{
		UserID:      userID,
		TenantID:    tenantID,
		MFARequired: false,
	})
}
