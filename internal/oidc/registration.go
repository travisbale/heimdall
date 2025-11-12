package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/travisbale/heimdall/internal/auth"
)

// RegistrationClient implements the Client interface using standard HTTP
type RegistrationClient struct {
	httpClient *http.Client
}

// NewRegistrationClient creates a new OIDC client with a default HTTP client
func NewRegistrationClient() *RegistrationClient {
	return &RegistrationClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Discover performs OIDC discovery to fetch provider metadata
// See: https://openid.net/specs/openid-connect-discovery-1_0.html
func (c *RegistrationClient) Discover(ctx context.Context, issuerURL string) (*auth.OIDCDiscoveryMetadata, error) {
	// Ensure issuer URL doesn't have trailing slash
	issuerURL = strings.TrimSuffix(issuerURL, "/")

	// Construct discovery endpoint
	discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", issuerURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create discovery request: %v", auth.ErrOIDCDiscoveryFailed, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch discovery document: %v", auth.ErrOIDCDiscoveryFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: discovery endpoint returned %d: %s", auth.ErrOIDCDiscoveryFailed, resp.StatusCode, string(body))
	}

	var metadata auth.OIDCDiscoveryMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("%w: failed to decode discovery document: %v", auth.ErrOIDCDiscoveryFailed, err)
	}

	if metadata.Issuer == "" {
		return nil, fmt.Errorf("%w: discovery document missing issuer", auth.ErrOIDCDiscoveryFailed)
	}

	// Validate issuer matches the URL used for discovery (prevents issuer confusion attacks)
	// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
	if metadata.Issuer != issuerURL {
		return nil, fmt.Errorf("%w: discovery document claims %q but was fetched from %q", auth.ErrOIDCIssuerMismatch, metadata.Issuer, issuerURL)
	}

	// Validate other required fields
	if metadata.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("%w: discovery document missing authorization_endpoint", auth.ErrOIDCDiscoveryFailed)
	}
	if metadata.TokenEndpoint == "" {
		return nil, fmt.Errorf("%w: discovery document missing token_endpoint", auth.ErrOIDCDiscoveryFailed)
	}
	if metadata.JWKSUri == "" {
		return nil, fmt.Errorf("%w: discovery document missing jwks_uri", auth.ErrOIDCDiscoveryFailed)
	}

	return &metadata, nil
}

// oidcRegistrationRequest represents an RFC 7591 client registration request
// See: https://datatracker.ietf.org/doc/html/rfc7591#section-2
type oidcRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name"`
	Scope                   string   `json:"scope,omitempty"`
}

// Register registers a new OAuth client with the OIDC provider
// See: https://datatracker.ietf.org/doc/html/rfc7591
func (c *RegistrationClient) Register(ctx context.Context, registrationEndpoint, callbackURL, clientName, accessToken string, scopes []string) (*auth.OIDCRegistration, error) {
	if registrationEndpoint == "" {
		return nil, fmt.Errorf("%w: provider does not support dynamic client registration", auth.ErrOIDCRegistrationFailed)
	}

	// Build registration request
	regReq := oidcRegistrationRequest{
		RedirectURIs:            []string{callbackURL},
		TokenEndpointAuthMethod: "client_secret_basic", // Most common method
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              clientName,
		Scope:                   strings.Join(scopes, " "),
	}

	body, err := json.Marshal(regReq)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal registration request: %v", auth.ErrOIDCRegistrationFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create registration request: %v", auth.ErrOIDCRegistrationFailed, err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add Authorization header if access token provided (for authenticated registration)
	if accessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	}

	// Register the OAuth client with the OIDC provider
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to register client: %v", auth.ErrOIDCRegistrationFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: registration endpoint returned %d: %s", auth.ErrOIDCRegistrationFailed, resp.StatusCode, string(bodyBytes))
	}

	var registration auth.OIDCRegistration
	if err := json.NewDecoder(resp.Body).Decode(&registration); err != nil {
		return nil, fmt.Errorf("%w: failed to decode registration response: %v", auth.ErrOIDCRegistrationFailed, err)
	}

	// Validate client ID
	if registration.ClientID == "" {
		return nil, fmt.Errorf("%w: registration is missing client_id", auth.ErrOIDCRegistrationFailed)
	}

	// We requested client_secret_basic auth, so we need a secret
	if registration.ClientSecret == "" {
		return nil, fmt.Errorf("%w: registration is missing client_secret", auth.ErrOIDCRegistrationFailed)
	}

	// RFC 7592: RegistrationAccessToken and RegistrationClientURI should come together
	// These are used for client management (update/delete operations)
	hasToken := registration.RegistrationAccessToken != ""
	hasURI := registration.RegistrationClientURI != ""
	if hasToken != hasURI {
		return nil, fmt.Errorf("%w: incomplete registration management credentials (got token=%v, uri=%v)", auth.ErrOIDCRegistrationFailed, hasToken, hasURI)
	}

	return &registration, nil
}

// Unregister deletes a dynamically registered client
// See: https://datatracker.ietf.org/doc/html/rfc7592#section-2.3
func (c *RegistrationClient) Unregister(ctx context.Context, registrationClientURI, registrationAccessToken string) error {
	// Handle empty URI - nothing to clean up
	if registrationClientURI == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, registrationClientURI, nil)
	if err != nil {
		return fmt.Errorf("failed to create unregister request: %w", err)
	}

	// Add Authorization header if access token provided
	if registrationAccessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", registrationAccessToken))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to unregister client: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 204 No Content is expected for successful deletion
	// 404 Not Found is acceptable (client already deleted)
	// 401 Unauthorized might indicate the registration_access_token expired
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unregister endpoint returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}
