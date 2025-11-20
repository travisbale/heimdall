package http

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

// OIDCAuthHandler handles OAuth/OIDC authentication flows (individual OAuth and corporate SSO)
type OIDCAuthHandler struct {
	oidcService  oidcService
	tokenService tokenService
}

func NewOIDCAuthHandler(config *Config) *OIDCAuthHandler {
	return &OIDCAuthHandler{
		oidcService:  config.OIDCService,
		tokenService: config.TokenService,
	}
}

// Login initiates an individual OAuth login flow for personal accounts (Google, GitHub, etc.)
func (h *OIDCAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req sdk.OIDCLoginRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	// Start individual OAuth login flow using system-wide provider configuration
	authURL, err := h.oidcService.StartOIDCLogin(r.Context(), req.ProviderType)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrOIDCProviderNotConfigured):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: fmt.Sprintf("OAuth provider '%s' is not configured on this server", req.ProviderType)})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to start OAuth login"})
		}
		return
	}

	respondJSON(w, http.StatusOK, sdk.OIDCAuthResponse{
		AuthorizationURL: authURL,
	})
}

// SSOLogin initiates a corporate SSO login flow for enterprise domains
func (h *OIDCAuthHandler) SSOLogin(w http.ResponseWriter, r *http.Request) {
	var req sdk.SSOLoginRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	// Start corporate SSO login flow using tenant-specific provider
	authURL, err := h.oidcService.StartSSOLogin(r.Context(), req.Email)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrSSONotConfigured):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "SSO is not configured for your domain. Please contact your administrator or use individual OAuth login."})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to start SSO login"})
		}
		return
	}

	respondJSON(w, http.StatusOK, sdk.OIDCAuthResponse{
		AuthorizationURL: authURL,
	})
}

// Callback handles the OAuth callback after user authorization at the provider
// Exchanges authorization code for tokens and creates or links user account
func (h *OIDCAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	// Parse callback parameters from OAuth provider redirect
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errorCode := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")

	// Handle authorization denial or provider errors
	if errorCode != "" {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: errorDescription})
		return
	}

	// Validate required parameters for success case
	if state == "" {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Missing state parameter"})
		return
	}
	if code == "" {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Missing code parameter"})
		return
	}

	// Exchange code for tokens, fetch user info, and create/link account
	user, _, err := h.oidcService.HandleOIDCCallback(r.Context(), state, code)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrOIDCSessionNotFound):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid or expired OAuth session"})

		case errors.Is(err, auth.ErrOIDCProviderNotFound), errors.Is(err, auth.ErrOIDCProviderNotConfigured):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "OAuth provider not configured"})

		case errors.Is(err, auth.ErrAutoProvisioningDisabled):
			respondJSON(w, http.StatusForbidden, sdk.ErrorResponse{Error: "Account not found and auto-provisioning is disabled"})

		case errors.Is(err, auth.ErrProviderEmailNotVerified):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Email must be verified by your OAuth provider"})

		case errors.Is(err, auth.ErrEmailConflict):
			respondJSON(w, http.StatusConflict, sdk.ErrorResponse{Error: "This email address is associated with an existing account. Please contact your administrator."})

		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to process OAuth callback"})
		}
		return
	}

	// Issue JWT tokens to complete login (MFA not required for OAuth)
	h.tokenService.IssueTokens(r.Context(), w, r, &Subject{
		UserID:      user.ID,
		TenantID:    user.TenantID,
		MFARequired: false,
	})
}
