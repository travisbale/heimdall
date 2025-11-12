package http

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

type OIDCAuthHandler struct {
	oidcService   oidcService
	userService   userService
	jwtService    jwtService
	secureCookies bool
}

func NewOIDCAuthHandler(oidcService oidcService, userService userService, jwtService jwtService, secureCookies bool) *OIDCAuthHandler {
	return &OIDCAuthHandler{
		oidcService:   oidcService,
		userService:   userService,
		jwtService:    jwtService,
		secureCookies: secureCookies,
	}
}

// Login initiates an individual OAuth login flow
func (h *OIDCAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req sdk.OIDCLoginRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	// Start individual OAuth login flow
	authURL, err := h.oidcService.StartOIDCLogin(r.Context(), req.ProviderType)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrOIDCProviderNotConfigured):
			respondError(w, http.StatusNotFound, fmt.Sprintf("OAuth provider '%s' is not configured on this server", req.ProviderType), err)
		default:
			respondError(w, http.StatusInternalServerError, "Failed to start OAuth login", err)
		}
		return
	}

	respondJSON(w, http.StatusOK, sdk.OIDCAuthResponse{
		AuthorizationURL: authURL,
	})
}

// SSOLogin initiates a corporate SSO login flow
func (h *OIDCAuthHandler) SSOLogin(w http.ResponseWriter, r *http.Request) {
	var req sdk.SSOLoginRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	// Extract domain from email (email is already validated)
	domain := extractDomainFromEmail(req.Email)

	// Start corporate SSO login flow (auto-detects provider)
	authURL, err := h.oidcService.StartSSOLogin(r.Context(), domain)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrSSONotConfigured):
			respondError(w, http.StatusNotFound, "SSO is not configured for your domain. Please contact your administrator or use individual OAuth login.", err)
		default:
			respondError(w, http.StatusInternalServerError, "Failed to start SSO login", err)
		}
		return
	}

	respondJSON(w, http.StatusOK, sdk.OIDCAuthResponse{
		AuthorizationURL: authURL,
	})
}

// Callback handles the OAuth callback after user authorization
func (h *OIDCAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	// Parse callback parameters from OAuth provider redirect
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errorCode := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")

	// Check for OAuth errors from provider
	if errorCode != "" {
		respondError(w, http.StatusBadRequest, errorDescription, fmt.Errorf("oauth error: %s", errorCode))
		return
	}

	// Validate required parameters for success case
	if state == "" {
		respondError(w, http.StatusBadRequest, "Missing state parameter", fmt.Errorf("state is required"))
		return
	}
	if code == "" {
		respondError(w, http.StatusBadRequest, "Missing code parameter", fmt.Errorf("code is required"))
		return
	}

	// Handle OAuth callback
	user, _, err := h.oidcService.HandleOIDCCallback(r.Context(), state, code)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrOIDCSessionNotFound):
			respondError(w, http.StatusBadRequest, "Invalid or expired OAuth session", err)

		case errors.Is(err, auth.ErrOIDCProviderNotFound), errors.Is(err, auth.ErrOIDCProviderNotConfigured):
			respondError(w, http.StatusBadRequest, "OAuth provider not configured", err)

		case errors.Is(err, auth.ErrAutoProvisioningDisabled):
			respondError(w, http.StatusForbidden, "Account not found and auto-provisioning is disabled", err)

		case errors.Is(err, auth.ErrProviderEmailNotVerified):
			respondError(w, http.StatusBadRequest, "Email must be verified by your OAuth provider", err)

		default:
			respondError(w, http.StatusInternalServerError, "Failed to process OAuth callback", err)
		}
		return
	}

	// Issue JWT tokens
	issueTokens(r.Context(), w, r, h.userService, h.jwtService, user.ID, user.TenantID, h.secureCookies)
}

// extractDomainFromEmail extracts the domain portion from an email address
// Assumes the email is already validated (contains @ symbol)
func extractDomainFromEmail(email string) string {
	// Find the @ symbol (searching from the end for efficiency)
	atIndex := -1
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			atIndex = i
			break
		}
	}
	return email[atIndex+1:]
}
