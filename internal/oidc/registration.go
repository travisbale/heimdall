package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/travisbale/heimdall/internal/iam"
)

// RegistrationClient handles OIDC discovery and RFC 7591 dynamic client registration
type RegistrationClient struct {
	httpClient *http.Client
}

func NewRegistrationClient() *RegistrationClient {
	return &RegistrationClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Discover performs OIDC discovery to fetch provider metadata from .well-known endpoint
func (c *RegistrationClient) Discover(ctx context.Context, issuerURL string) (*iam.OIDCDiscoveryMetadata, error) {
	issuerURL = strings.TrimSuffix(issuerURL, "/")

	// Construct discovery endpoint
	discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", issuerURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create discovery request: %v", iam.ErrOIDCDiscoveryFailed, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch discovery document: %v", iam.ErrOIDCDiscoveryFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: discovery endpoint returned %d: %s", iam.ErrOIDCDiscoveryFailed, resp.StatusCode, string(body))
	}

	var metadata iam.OIDCDiscoveryMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("%w: failed to decode discovery document: %v", iam.ErrOIDCDiscoveryFailed, err)
	}

	if metadata.Issuer == "" {
		return nil, fmt.Errorf("%w: discovery document missing issuer", iam.ErrOIDCDiscoveryFailed)
	}

	// Validate issuer matches discovery URL to prevent issuer confusion attacks
	if metadata.Issuer != issuerURL {
		return nil, fmt.Errorf("%w: discovery document claims %q but was fetched from %q", iam.ErrOIDCIssuerMismatch, metadata.Issuer, issuerURL)
	}

	// Validate other required fields
	if metadata.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("%w: discovery document missing authorization_endpoint", iam.ErrOIDCDiscoveryFailed)
	}
	if metadata.TokenEndpoint == "" {
		return nil, fmt.Errorf("%w: discovery document missing token_endpoint", iam.ErrOIDCDiscoveryFailed)
	}
	if metadata.JWKSUri == "" {
		return nil, fmt.Errorf("%w: discovery document missing jwks_uri", iam.ErrOIDCDiscoveryFailed)
	}

	return &metadata, nil
}

// oidcRegistrationRequest represents RFC 7591 dynamic client registration
type oidcRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name"`
	Scope                   string   `json:"scope,omitempty"`
}

// Register dynamically registers a new OAuth client with the OIDC provider (RFC 7591)
func (c *RegistrationClient) Register(ctx context.Context, registrationEndpoint, callbackURL, clientName, accessToken string, scopes []string) (*iam.OIDCRegistration, error) {
	if registrationEndpoint == "" {
		return nil, fmt.Errorf("%w: provider does not support dynamic client registration", iam.ErrOIDCRegistrationFailed)
	}

	regReq := oidcRegistrationRequest{
		RedirectURIs:            []string{callbackURL},
		TokenEndpointAuthMethod: "client_secret_basic", // Most widely supported auth method
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              clientName,
		Scope:                   strings.Join(scopes, " "),
	}

	body, err := json.Marshal(regReq)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal registration request: %v", iam.ErrOIDCRegistrationFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create registration request: %v", iam.ErrOIDCRegistrationFailed, err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Some providers require bearer token for registration (e.g., Okta)
	if accessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to register client: %v", iam.ErrOIDCRegistrationFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: registration endpoint returned %d: %s", iam.ErrOIDCRegistrationFailed, resp.StatusCode, string(bodyBytes))
	}

	var registration iam.OIDCRegistration
	if err := json.NewDecoder(resp.Body).Decode(&registration); err != nil {
		return nil, fmt.Errorf("%w: failed to decode registration response: %v", iam.ErrOIDCRegistrationFailed, err)
	}

	// Validate client ID
	if registration.ClientID == "" {
		return nil, fmt.Errorf("%w: registration is missing client_id", iam.ErrOIDCRegistrationFailed)
	}

	// Client secret required for client_secret_basic auth method
	if registration.ClientSecret == "" {
		return nil, fmt.Errorf("%w: registration is missing client_secret", iam.ErrOIDCRegistrationFailed)
	}

	// RFC 7592: access token and URI must both be present or both absent
	hasToken := registration.RegistrationAccessToken != ""
	hasURI := registration.RegistrationClientURI != ""
	if hasToken != hasURI {
		return nil, fmt.Errorf("%w: incomplete registration management credentials (got token=%v, uri=%v)", iam.ErrOIDCRegistrationFailed, hasToken, hasURI)
	}

	return &registration, nil
}

// Unregister deletes a dynamically registered client (RFC 7592)
func (c *RegistrationClient) Unregister(ctx context.Context, registrationClientURI, registrationAccessToken string) error {
	if registrationClientURI == "" {
		return nil // No client to unregister
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

	// Accept both 204 (success) and 404 (already deleted) as success
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unregister endpoint returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}
