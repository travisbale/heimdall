package http

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
)

// OIDCAuthHandler handles OAuth/OIDC authentication flows (individual OAuth and corporate SSO)
type OIDCAuthHandler struct {
	OIDCAuthService oidcAuthService
	AuthService     authService
	SecureCookies   bool
}

// Login initiates an individual OAuth login flow for personal accounts (Google, GitHub, etc.)
func (h *OIDCAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req sdk.OIDCLoginRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	// Start individual OAuth login flow using system-wide provider configuration
	authURL, err := h.OIDCAuthService.StartOIDCLogin(r.Context(), req.ProviderType)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCProviderNotConfigured):
			api.RespondError(w, http.StatusNotFound, fmt.Sprintf("OAuth provider '%s' is not configured on this server", req.ProviderType), err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to start OAuth login", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusOK, sdk.OIDCAuthResponse{
		AuthorizationURL: authURL,
	})
}

// SSOLogin initiates a corporate SSO login flow for enterprise domains
func (h *OIDCAuthHandler) SSOLogin(w http.ResponseWriter, r *http.Request) {
	var req sdk.SSOLoginRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	// Start corporate SSO login flow using tenant-specific provider
	authURL, err := h.OIDCAuthService.StartSSOLogin(r.Context(), req.Email)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrSSONotConfigured):
			api.RespondError(w, http.StatusBadRequest, "SSO is not configured for your domain. Please contact your administrator or use individual OAuth login.", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to start SSO login", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusOK, sdk.OIDCAuthResponse{
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
		api.RespondError(w, http.StatusBadRequest, errorDescription, nil)
		return
	}

	// Validate required parameters for success case
	if state == "" {
		api.RespondError(w, http.StatusBadRequest, "Missing state parameter", nil)
		return
	}
	if code == "" {
		api.RespondError(w, http.StatusBadRequest, "Missing code parameter", nil)
		return
	}

	// Exchange code for tokens, fetch user info, create/link account, and create session
	tokens, err := h.AuthService.AuthenticateWithOIDC(r.Context(), state, code)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCSessionNotFound):
			api.RespondError(w, http.StatusBadRequest, "Invalid or expired OAuth session", err)

		case errors.Is(err, iam.ErrOIDCProviderNotFound), errors.Is(err, iam.ErrOIDCProviderNotConfigured):
			api.RespondError(w, http.StatusBadRequest, "OAuth provider not configured", err)

		case errors.Is(err, iam.ErrAutoProvisioningDisabled):
			api.RespondError(w, http.StatusForbidden, "Account not found and auto-provisioning is disabled", err)

		case errors.Is(err, iam.ErrProviderEmailNotVerified):
			api.RespondError(w, http.StatusBadRequest, "Email must be verified by your OAuth provider", err)

		case errors.Is(err, iam.ErrEmailConflict):
			api.RespondError(w, http.StatusConflict, "This email address is associated with an existing account. Please contact your administrator.", err)

		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to process OAuth callback", err)
		}
		return
	}

	encodeSessionResponse(w, r, tokens, h.SecureCookies)
}
