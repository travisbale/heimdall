package rest

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
)

// listSupportedProviders returns OAuth providers available for individual login (not SSO)
// Public endpoint used by login UI to display "Login with Google" buttons
func (r *Router) listSupportedProviders(w http.ResponseWriter, req *http.Request) {
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

	r.writeJSON(w, http.StatusOK, sdk.OIDCProviderTypesResponse{
		Providers: providers,
	})
}

// CreateOIDCProvider creates a new OAuth provider configuration for corporate SSO
func (r *Router) createOIDCProvider(w http.ResponseWriter, req *http.Request) {
	var body sdk.CreateOIDCProviderRequest
	if !r.decodeAndValidateJSON(w, req, &body) {
		return
	}

	provider := &iam.OIDCProviderConfig{
		ProviderName:             body.ProviderName,
		IssuerURL:                body.IssuerURL,
		ClientID:                 body.ClientID,
		ClientSecret:             body.ClientSecret,
		Scopes:                   body.Scopes,
		Enabled:                  body.Enabled,
		AllowedDomains:           body.AllowedDomains,
		AutoCreateUsers:          body.AutoCreateUsers,
		RequireEmailVerification: body.RequireEmailVerification,
	}

	result, err := r.OIDCProviderService.CreateOIDCProvider(req.Context(), provider, body.AccessToken)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCDiscoveryFailed):
			r.writeError(req.Context(), w, http.StatusBadRequest, "Unable to discover OIDC provider. Check the issuer URL.", err)
		case errors.Is(err, iam.ErrOIDCIssuerMismatch):
			r.writeError(req.Context(), w, http.StatusBadRequest, "OIDC provider issuer validation failed", err)
		case errors.Is(err, iam.ErrOIDCRegistrationFailed):
			r.writeError(req.Context(), w, http.StatusBadRequest, "Dynamic client registration failed", err)
		default:
			r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to create OAuth provider", err)
		}
		return
	}

	r.writeJSON(w, http.StatusCreated, toSDKProvider(result))
}

// GetOIDCProvider retrieves an OIDC provider by ID
func (r *Router) getOIDCProvider(w http.ResponseWriter, req *http.Request) {
	body := sdk.GetOIDCProviderRequest{
		ProviderID: parseUUID(req.PathValue("providerID")),
	}

	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	provider, err := r.OIDCProviderService.GetOIDCProvider(req.Context(), body.ProviderID)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCProviderNotFound):
			r.writeError(req.Context(), w, http.StatusNotFound, "OAuth provider not found", err)
		default:
			r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to get OAuth provider", err)
		}
		return
	}

	r.writeJSON(w, http.StatusOK, toSDKProvider(provider))
}

// ListOIDCProviders lists all OAuth providers for the tenant
func (r *Router) listOIDCProviders(w http.ResponseWriter, req *http.Request) {
	providers, err := r.OIDCProviderService.ListOIDCProviders(req.Context())
	if err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to list OAuth providers", err)
		return
	}

	sdkProviders := make([]sdk.OIDCProvider, len(providers))
	for i, provider := range providers {
		sdkProviders[i] = toSDKProvider(provider)
	}

	r.writeJSON(w, http.StatusOK, sdk.OIDCProvidersResponse{
		Providers: sdkProviders,
	})
}

// UpdateOIDCProvider updates an OAuth provider configuration
func (r *Router) updateOIDCProvider(w http.ResponseWriter, req *http.Request) {
	var body sdk.UpdateOIDCProviderRequest
	if err := decodeJSON(req, &body); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	body.ProviderID = parseUUID(req.PathValue("providerID"))

	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	params := &iam.UpdateOIDCProviderParams{
		ID:                       body.ProviderID,
		ProviderName:             body.ProviderName,
		ClientSecret:             body.ClientSecret,
		Scopes:                   body.Scopes,
		Enabled:                  body.Enabled,
		AllowedDomains:           body.AllowedDomains,
		AutoCreateUsers:          body.AutoCreateUsers,
		RequireEmailVerification: body.RequireEmailVerification,
	}

	result, err := r.OIDCProviderService.UpdateOIDCProvider(req.Context(), params)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCProviderNotFound):
			r.writeError(req.Context(), w, http.StatusNotFound, "OAuth provider not found", err)
		default:
			r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to update OAuth provider", err)
		}
		return
	}

	r.writeJSON(w, http.StatusOK, toSDKProvider(result))
}

// DeleteOIDCProvider deletes an OAuth provider
func (r *Router) deleteOIDCProvider(w http.ResponseWriter, req *http.Request) {
	body := sdk.DeleteOIDCProviderRequest{
		ProviderID: parseUUID(req.PathValue("providerID")),
	}

	if err := body.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), err)
		return
	}

	err := r.OIDCProviderService.DeleteOIDCProvider(req.Context(), body.ProviderID)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrOIDCProviderNotFound):
			r.writeError(req.Context(), w, http.StatusNotFound, "OAuth provider not found", err)
		default:
			r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to delete OAuth provider", err)
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
