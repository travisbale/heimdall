package http

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
)

// ListSupportedProviders returns OAuth providers available for individual login (not SSO)
// Public endpoint used by login UI to display "Login with Google" buttons
func ListSupportedProviders(w http.ResponseWriter, r *http.Request) {
	providers := []sdk.OIDCProviderTypeInfo{
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

	respondJSON(w, http.StatusOK, sdk.OIDCProviderTypesResponse{
		Providers: providers,
	})
}

// OIDCProvidersHandler handles tenant-specific OIDC provider CRUD operations for corporate SSO
type OIDCProvidersHandler struct {
	oidcService oidcService
}

// NewOIDCProvidersHandler creates a new OIDC providers handler
func NewOIDCProvidersHandler(config *Config) *OIDCProvidersHandler {
	return &OIDCProvidersHandler{
		oidcService: config.OIDCService,
	}
}

// CreateOIDCProvider creates a new OAuth provider configuration for corporate SSO
func (h *OIDCProvidersHandler) CreateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	var req sdk.CreateOIDCProviderRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	provider := &iam.OIDCProviderConfig{
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
		case errors.Is(err, iam.ErrOIDCDiscoveryFailed):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Unable to discover OIDC provider. Check the issuer URL."})

		case errors.Is(err, iam.ErrOIDCIssuerMismatch):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "OIDC provider issuer validation failed"})

		case errors.Is(err, iam.ErrOIDCRegistrationFailed):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Dynamic client registration failed"})

		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to create OAuth provider"})
		}
		return
	}

	respondJSON(w, http.StatusCreated, convertProviderToSDK(result))
}

// GetOIDCProvider retrieves an OIDC provider by ID
func (h *OIDCProvidersHandler) GetOIDCProvider(w http.ResponseWriter, r *http.Request) {
	req := sdk.GetOIDCProviderRequest{
		ProviderID: parseUUID(chi.URLParam(r, "providerID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	provider, err := h.oidcService.GetOIDCProvider(r.Context(), req.ProviderID)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCProviderNotFound):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "OAuth provider not found"})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to get OAuth provider"})
		}
		return
	}

	respondJSON(w, http.StatusOK, convertProviderToSDK(provider))
}

// ListOIDCProviders lists all OAuth providers for the tenant
func (h *OIDCProvidersHandler) ListOIDCProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := h.oidcService.ListOIDCProviders(r.Context())
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to list OAuth providers"})
		return
	}

	sdkProviders := make([]sdk.OIDCProvider, len(providers))
	for i, provider := range providers {
		sdkProviders[i] = convertProviderToSDK(provider)
	}

	respondJSON(w, http.StatusOK, sdk.OIDCProvidersResponse{
		Providers: sdkProviders,
	})
}

// UpdateOIDCProvider updates an OAuth provider configuration
func (h *OIDCProvidersHandler) UpdateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	var req sdk.UpdateOIDCProviderRequest
	if err := decodeJSON(r, &req); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid request body"})
		return
	}

	req.ProviderID = parseUUID(chi.URLParam(r, "providerID"))

	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	params := &iam.UpdateOIDCProviderParams{
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
		case errors.Is(err, iam.ErrOIDCProviderNotFound):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "OAuth provider not found"})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to update OAuth provider"})
		}
		return
	}

	respondJSON(w, http.StatusOK, convertProviderToSDK(result))
}

// DeleteOIDCProvider deletes an OAuth provider
func (h *OIDCProvidersHandler) DeleteOIDCProvider(w http.ResponseWriter, r *http.Request) {
	req := sdk.DeleteOIDCProviderRequest{
		ProviderID: parseUUID(chi.URLParam(r, "providerID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return
	}

	err := h.oidcService.DeleteOIDCProvider(r.Context(), req.ProviderID)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCProviderNotFound):
			respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "OAuth provider not found"})
		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to delete OAuth provider"})
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// convertProviderToSDK converts internal provider config to API response format
func convertProviderToSDK(provider *iam.OIDCProviderConfig) sdk.OIDCProvider {
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
		RegistrationMethod:       provider.RegistrationMethod,
		ClientIDIssuedAt:         provider.ClientIDIssuedAt,
		ClientSecretExpiresAt:    provider.ClientSecretExpiresAt,
	}
}
