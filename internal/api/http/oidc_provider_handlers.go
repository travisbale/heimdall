package http

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

// ListSupportedProviders returns OAuth providers available for individual login (not SSO)
// Public endpoint used by login UI to display "Login with Google" buttons
func ListSupportedProviders(w http.ResponseWriter, r *http.Request) {
	providers := []sdk.SupportedOIDCProviderType{
		{
			Type:        sdk.OIDCProviderTypeGoogle,
			DisplayName: sdk.OIDCProviderTypeGoogle.DisplayName(),
		},
		{
			Type:        sdk.OIDCProviderTypeMicrosoft,
			DisplayName: sdk.OIDCProviderTypeMicrosoft.DisplayName(),
		},
		{
			Type:        sdk.OIDCProviderTypeGitHub,
			DisplayName: sdk.OIDCProviderTypeGitHub.DisplayName(),
		},
		{
			Type:        sdk.OIDCProviderTypeOkta,
			DisplayName: sdk.OIDCProviderTypeOkta.DisplayName(),
		},
	}

	respondJSON(w, http.StatusOK, sdk.ListSupportedOIDCProvidersResponse{
		Providers: providers,
	})
}

// OIDCProvidersHandler handles tenant-specific OIDC provider CRUD operations for corporate SSO
type OIDCProvidersHandler struct {
	oidcService oidcService
}

// NewOIDCProvidersHandler creates a new OIDC providers handler
func NewOIDCProvidersHandler(oidcService oidcService) *OIDCProvidersHandler {
	return &OIDCProvidersHandler{
		oidcService: oidcService,
	}
}

// CreateProvider creates a new OAuth provider configuration for corporate SSO
// Performs OIDC discovery and optionally dynamic client registration
func (h *OIDCProvidersHandler) CreateProvider(w http.ResponseWriter, r *http.Request) {
	var req sdk.CreateOIDCProviderRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	provider := &auth.OIDCProviderConfig{
		ProviderName:             req.ProviderName,
		IssuerURL:                req.IssuerURL,
		ClientID:                 req.ClientID,
		ClientSecret:             req.ClientSecret,
		Scopes:                   req.Scopes,
		Enabled:                  req.Enabled,
		AllowedDomains:           req.AllowedDomains,
		AutoCreateUsers:          req.AutoCreateUsers,
		RequireEmailVerification: req.RequireEmailVerification,
	}

	result, err := h.oidcService.CreateOIDCProvider(r.Context(), provider, req.AccessToken)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrOIDCDiscoveryFailed):
			respondError(w, http.StatusBadRequest, "Unable to discover OIDC provider. Check the issuer URL.", err)

		case errors.Is(err, auth.ErrOIDCIssuerMismatch):
			respondError(w, http.StatusBadRequest, "OIDC provider issuer validation failed", err)

		case errors.Is(err, auth.ErrOIDCRegistrationFailed):
			respondError(w, http.StatusBadRequest, "Dynamic client registration failed", err)

		default:
			respondError(w, http.StatusInternalServerError, "Failed to create OAuth provider", err)
		}
		return
	}

	respondJSON(w, http.StatusCreated, sdk.OIDCProviderResponse{
		Provider: convertProviderToSDK(result),
	})
}

// GetProvider retrieves an OIDC provider by ID
func (h *OIDCProvidersHandler) GetProvider(w http.ResponseWriter, r *http.Request) {
	req := sdk.GetOIDCProviderRequest{
		ProviderID: parseUUID(chi.URLParam(r, "providerID")),
	}

	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	provider, err := h.oidcService.GetOIDCProvider(r.Context(), req.ProviderID)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrOIDCProviderNotFound):
			respondError(w, http.StatusNotFound, "OAuth provider not found", err)
		default:
			respondError(w, http.StatusInternalServerError, "Failed to get OAuth provider", err)
		}
		return
	}

	respondJSON(w, http.StatusOK, sdk.OIDCProviderResponse{
		Provider: convertProviderToSDK(provider),
	})
}

// ListProviders lists all OAuth providers for the tenant
func (h *OIDCProvidersHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := h.oidcService.ListOIDCProviders(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to list OAuth providers", err)
		return
	}

	sdkProviders := make([]sdk.OIDCProvider, len(providers))
	for i, provider := range providers {
		sdkProviders[i] = convertProviderToSDK(provider)
	}

	respondJSON(w, http.StatusOK, sdk.ListOIDCProvidersResponse{
		Providers: sdkProviders,
	})
}

// UpdateProvider updates an OAuth provider configuration
func (h *OIDCProvidersHandler) UpdateProvider(w http.ResponseWriter, r *http.Request) {
	var req sdk.UpdateOIDCProviderRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	req.ProviderID = parseUUID(chi.URLParam(r, "providerID"))

	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	params := &auth.UpdateOIDCProviderParams{
		ID:                       req.ProviderID,
		ProviderName:             req.ProviderName,
		ClientSecret:             req.ClientSecret,
		Scopes:                   req.Scopes,
		Enabled:                  req.Enabled,
		AllowedDomains:           req.AllowedDomains,
		AutoCreateUsers:          req.AutoCreateUsers,
		RequireEmailVerification: req.RequireEmailVerification,
	}

	result, err := h.oidcService.UpdateOIDCProvider(r.Context(), params)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrOIDCProviderNotFound):
			respondError(w, http.StatusNotFound, "OAuth provider not found", err)
		default:
			respondError(w, http.StatusInternalServerError, "Failed to update OAuth provider", err)
		}
		return
	}

	respondJSON(w, http.StatusOK, sdk.OIDCProviderResponse{
		Provider: convertProviderToSDK(result),
	})
}

// DeleteProvider deletes an OAuth provider
func (h *OIDCProvidersHandler) DeleteProvider(w http.ResponseWriter, r *http.Request) {
	req := sdk.DeleteOIDCProviderRequest{
		ProviderID: parseUUID(chi.URLParam(r, "providerID")),
	}

	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	err := h.oidcService.DeleteOIDCProvider(r.Context(), req.ProviderID)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrOIDCProviderNotFound):
			respondError(w, http.StatusNotFound, "OAuth provider not found", err)
		default:
			respondError(w, http.StatusInternalServerError, "Failed to delete OAuth provider", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// convertProviderToSDK converts internal provider config to API response format
// Excludes client secret from responses for security
func convertProviderToSDK(provider *auth.OIDCProviderConfig) sdk.OIDCProvider {
	return sdk.OIDCProvider{
		ID:                       provider.ID,
		ProviderName:             provider.ProviderName,
		IssuerURL:                provider.IssuerURL,
		ClientID:                 provider.ClientID,
		Scopes:                   provider.Scopes,
		Enabled:                  provider.Enabled,
		AllowedDomains:           provider.AllowedDomains,
		AutoCreateUsers:          provider.AutoCreateUsers,
		RequireEmailVerification: provider.RequireEmailVerification,
		RegistrationMethod:       sdk.OIDCRegistrationMethod(provider.RegistrationMethod),
		ClientIDIssuedAt:         provider.ClientIDIssuedAt,
		ClientSecretExpiresAt:    provider.ClientSecretExpiresAt,
		CreatedAt:                provider.CreatedAt,
		UpdatedAt:                provider.UpdatedAt,
	}
}
