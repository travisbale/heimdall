package http

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/travisbale/heimdall/identity"
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
		respondError(w, http.StatusInternalServerError, "Failed to start OAuth login", err)
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
		// Return appropriate status code based on error type
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

// LinkProvider initiates an OAuth link flow
func (h *OIDCAuthHandler) LinkProvider(w http.ResponseWriter, r *http.Request) {
	var req sdk.OIDCLinkRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	// Extract authenticated user
	userID, err := identity.GetUser(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get user context", err)
		return
	}

	// Start OAuth link flow
	authURL, err := h.oidcService.StartOIDCLink(r.Context(), userID, req.ProviderID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to start OAuth link", err)
		return
	}

	respondJSON(w, http.StatusOK, sdk.OIDCAuthResponse{
		AuthorizationURL: authURL,
	})
}

// Callback handles the OAuth callback after user authorization
func (h *OIDCAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	req := sdk.OIDCCallbackRequest{
		State:            r.URL.Query().Get("state"),
		Code:             r.URL.Query().Get("code"),
		Error:            r.URL.Query().Get("error"),
		ErrorDescription: r.URL.Query().Get("error_description"),
	}

	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid callback parameters", err)
		return
	}

	// Check for OAuth errors from provider
	if req.Error != "" {
		respondError(w, http.StatusBadRequest, req.ErrorDescription, fmt.Errorf("oauth error: %s", req.Error))
		return
	}

	// Handle OAuth callback
	user, link, err := h.oidcService.HandleOIDCCallback(r.Context(), req.State, req.Code)
	if err != nil {
		if errors.Is(err, auth.ErrOIDCSessionNotFound) {
			respondError(w, http.StatusBadRequest, "Invalid or expired OAuth session", err)
			return
		}
		if errors.Is(err, auth.ErrOIDCProviderNotFound) {
			respondError(w, http.StatusNotFound, "OAuth provider not configured", err)
			return
		}
		if errors.Is(err, auth.ErrOIDCLinkAlreadyExists) {
			respondError(w, http.StatusConflict, "Provider already linked to this account", err)
			return
		}
		if errors.Is(err, auth.ErrOIDCProviderAccountAlreadyLinked) {
			respondError(w, http.StatusConflict, "This provider account is already linked to another user", err)
			return
		}
		respondError(w, http.StatusInternalServerError, "Failed to process OAuth callback", err)
		return
	}

	// Check if this was a link operation (user will be nil)
	if user == nil {
		// Link operation - return the link information
		resp := sdk.OIDCLinkResponse{
			Link: sdk.OIDCLink{
				ID:            link.ID,
				ProviderID:    link.OIDCProviderID,
				ProviderEmail: link.ProviderEmail,
				LinkedAt:      link.LinkedAt,
				LastUsedAt:    link.LastUsedAt,
			},
		}

		respondJSON(w, http.StatusOK, resp)
		return
	}

	// Login operation - issue JWT tokens
	issueTokens(r.Context(), w, r, h.userService, h.jwtService, user.ID, user.TenantID, h.secureCookies)
}

// UnlinkProvider removes an OAuth provider link from the authenticated user
func (h *OIDCAuthHandler) UnlinkProvider(w http.ResponseWriter, r *http.Request) {
	userID, err := identity.GetUser(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get user context", err)
		return
	}

	// Get provider ID from URL parameter
	req := sdk.OIDCUnlinkRequest{
		ProviderID: parseUUID(chi.URLParam(r, "providerID")),
	}

	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	// Unlink OAuth provider
	err = h.oidcService.UnlinkOIDCProvider(r.Context(), userID, req.ProviderID)
	if err != nil {
		if errors.Is(err, auth.ErrOIDCLinkNotFound) {
			respondError(w, http.StatusNotFound, "OAuth link not found", err)
			return
		}

		respondError(w, http.StatusInternalServerError, "Failed to unlink OAuth provider", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListProviderLinks lists all OAuth provider links for the authenticated user
func (h *OIDCAuthHandler) ListProviderLinks(w http.ResponseWriter, r *http.Request) {
	userID, err := identity.GetUser(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get user context", err)
		return
	}

	// List OAuth links
	links, err := h.oidcService.ListUserOIDCLinks(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to list OAuth providers", err)
		return
	}

	// Convert to response format
	responseLinks := make([]sdk.OIDCLink, len(links))
	for i, link := range links {
		responseLinks[i] = sdk.OIDCLink{
			ID:            link.ID,
			ProviderID:    link.OIDCProviderID,
			ProviderEmail: link.ProviderEmail,
			LinkedAt:      link.LinkedAt,
			LastUsedAt:    link.LastUsedAt,
		}
	}

	respondJSON(w, http.StatusOK, sdk.OIDCListLinksResponse{
		Links: responseLinks,
	})
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
