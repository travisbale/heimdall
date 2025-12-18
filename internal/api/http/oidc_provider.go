package http

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
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

	api.RespondJSON(w, http.StatusOK, sdk.OIDCProviderTypesResponse{
		Providers: providers,
	})
}

// OIDCProvidersHandler handles tenant-specific OIDC provider CRUD operations for corporate SSO
type OIDCProvidersHandler struct {
	OIDCProviderService oidcProviderService
}

// CreateOIDCProvider creates a new OAuth provider configuration for corporate SSO
func (h *OIDCProvidersHandler) CreateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	var req sdk.CreateOIDCProviderRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
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

	result, err := h.OIDCProviderService.CreateOIDCProvider(r.Context(), provider, req.AccessToken)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCDiscoveryFailed):
			api.RespondError(w, http.StatusBadRequest, "Unable to discover OIDC provider. Check the issuer URL.", err)
		case errors.Is(err, iam.ErrOIDCIssuerMismatch):
			api.RespondError(w, http.StatusBadRequest, "OIDC provider issuer validation failed", err)
		case errors.Is(err, iam.ErrOIDCRegistrationFailed):
			api.RespondError(w, http.StatusBadRequest, "Dynamic client registration failed", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to create OAuth provider", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusCreated, toSDKProvider(result))
}

// GetOIDCProvider retrieves an OIDC provider by ID
func (h *OIDCProvidersHandler) GetOIDCProvider(w http.ResponseWriter, r *http.Request) {
	req := sdk.GetOIDCProviderRequest{
		ProviderID: api.ParseUUID(chi.URLParam(r, "providerID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	provider, err := h.OIDCProviderService.GetOIDCProvider(r.Context(), req.ProviderID)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCProviderNotFound):
			api.RespondError(w, http.StatusNotFound, "OAuth provider not found", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to get OAuth provider", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusOK, toSDKProvider(provider))
}

// ListOIDCProviders lists all OAuth providers for the tenant
func (h *OIDCProvidersHandler) ListOIDCProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := h.OIDCProviderService.ListOIDCProviders(r.Context())
	if err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to list OAuth providers", err)
		return
	}

	sdkProviders := make([]sdk.OIDCProvider, len(providers))
	for i, provider := range providers {
		sdkProviders[i] = toSDKProvider(provider)
	}

	api.RespondJSON(w, http.StatusOK, sdk.OIDCProvidersResponse{
		Providers: sdkProviders,
	})
}

// UpdateOIDCProvider updates an OAuth provider configuration
func (h *OIDCProvidersHandler) UpdateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	var req sdk.UpdateOIDCProviderRequest
	if err := api.DecodeJSON(r, &req); err != nil {
		api.RespondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	req.ProviderID = api.ParseUUID(chi.URLParam(r, "providerID"))

	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
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

	result, err := h.OIDCProviderService.UpdateOIDCProvider(r.Context(), params)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCProviderNotFound):
			api.RespondError(w, http.StatusNotFound, "OAuth provider not found", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to update OAuth provider", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusOK, toSDKProvider(result))
}

// DeleteOIDCProvider deletes an OAuth provider
func (h *OIDCProvidersHandler) DeleteOIDCProvider(w http.ResponseWriter, r *http.Request) {
	req := sdk.DeleteOIDCProviderRequest{
		ProviderID: api.ParseUUID(chi.URLParam(r, "providerID")),
	}

	if err := req.Validate(r.Context()); err != nil {
		api.RespondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	err := h.OIDCProviderService.DeleteOIDCProvider(r.Context(), req.ProviderID)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCProviderNotFound):
			api.RespondError(w, http.StatusNotFound, "OAuth provider not found", err)
		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to delete OAuth provider", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// toSDKProvider converts internal provider config to API response format
func toSDKProvider(provider *iam.OIDCProviderConfig) sdk.OIDCProvider {
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
