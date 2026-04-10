package http

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
)

// OAuthLogin initiates an individual OAuth login flow for personal accounts (Google, GitHub, etc.)
func (r *Router) oauthLogin(w http.ResponseWriter, req *http.Request) {
	var body sdk.OIDCLoginRequest
	if !api.DecodeAndValidateJSON(w, req, &body) {
		return
	}

	// Start individual OAuth login flow using system-wide provider configuration
	authURL, err := r.OIDCAuthService.StartOIDCLogin(req.Context(), body.ProviderType)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCProviderNotConfigured):
			api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("OAuth provider '%s' is not configured on this server", body.ProviderType), err)
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
func (r *Router) ssoLogin(w http.ResponseWriter, req *http.Request) {
	var body sdk.SSOLoginRequest
	if !api.DecodeAndValidateJSON(w, req, &body) {
		return
	}

	// Start corporate SSO login flow using tenant-specific provider
	authURL, err := r.OIDCAuthService.StartSSOLogin(req.Context(), body.Email)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrSSONotConfigured):
			api.RespondError(w, http.StatusBadRequest, "SSO is not configured for your domain", nil)
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
func (r *Router) oauthCallback(w http.ResponseWriter, req *http.Request) {
	// Parse callback parameters from OAuth provider redirect
	state := req.URL.Query().Get("state")
	code := req.URL.Query().Get("code")
	errorCode := req.URL.Query().Get("error")
	errorDescription := req.URL.Query().Get("error_description")

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
	tokens, err := r.AuthService.AuthenticateWithOIDC(req.Context(), state, code)
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

	encodeSessionResponse(w, req, tokens, r.SecureCookies)
}
