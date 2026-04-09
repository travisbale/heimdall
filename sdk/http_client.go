package sdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// validatable interface for requests that support validation
type validatable interface {
	Validate(ctx context.Context) error
}

// HTTPClient is an HTTP client for the heimdall API
type HTTPClient struct {
	*http.Client // Embedded for direct access to http.Client methods
	baseURL      string
	accessToken  string
}

// Option is a functional option for configuring the HTTPClient
type Option func(*HTTPClient)

// WithHTTPClient allows setting a custom http.Client
// Note: If you provide a custom client for refresh token support,
// ensure it has a cookie jar configured
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *HTTPClient) {
		c.Client = httpClient
	}
}

// WithCookieJar configures the client with a specific cookie jar.
// Useful for tests that need to inspect cookies (e.g., capturing refresh tokens).
func WithCookieJar(jar *cookiejar.Jar) Option {
	return func(c *HTTPClient) {
		c.Client = &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{},
			},
		}
	}
}

// WithInsecureSkipVerify configures the client to skip TLS certificate verification
// This is useful for development with self-signed certificates
func WithInsecureSkipVerify() Option {
	return func(c *HTTPClient) {
		if transport, ok := c.Transport.(*http.Transport); ok {
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{}
			}
			transport.TLSClientConfig.InsecureSkipVerify = true
		}
	}
}

// NewHTTPClient creates a new heimdall API client
// The client automatically handles cookies for refresh token management
func NewHTTPClient(baseURL string, opts ...Option) (*HTTPClient, error) {
	// Create a cookie jar to automatically handle refresh token cookies
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	client := &HTTPClient{
		baseURL: baseURL,
		Client: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{},
			},
		},
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// Health checks the health of the heimdall API.
// Returns nil if healthy, error if unhealthy or unreachable.
func (c *HTTPClient) Health(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s%s", c.baseURL, RouteHealth)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("service unhealthy: status %d", resp.StatusCode)
	}

	return nil
}

// Login authenticates a user and returns an access token
// The access token is automatically set on the client for subsequent authenticated requests
// The refresh token is automatically stored in the client's cookie jar
// If MFA is required, returns MFAChallengeToken or MFASetupToken instead of AccessToken
func (c *HTTPClient) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	var resp LoginResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1Login, &req, &resp); err != nil {
		return nil, err
	}

	if resp.AccessToken != "" {
		c.accessToken = resp.AccessToken
	}

	return &resp, nil
}

// Logout logs out the current user by revoking the refresh token
func (c *HTTPClient) Logout(ctx context.Context) (*LogoutResponse, error) {
	var resp LogoutResponse
	if err := c.doRequest(ctx, http.MethodDelete, RouteV1Refresh, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetMe retrieves the current authenticated user's profile
func (c *HTTPClient) GetMe(ctx context.Context) (*User, error) {
	var user User
	if err := c.doRequest(ctx, http.MethodGet, RouteV1Me, nil, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// RefreshToken refreshes the access token using the refresh token cookie
// The access token is automatically set on the client for subsequent authenticated requests
// The refresh token cookie must have been set by a previous Login call
func (c *HTTPClient) RefreshToken(ctx context.Context) (*LoginResponse, error) {
	var resp LoginResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1Refresh, nil, &resp); err != nil {
		return nil, err
	}
	c.accessToken = resp.AccessToken
	return &resp, nil
}

// Register registers a new user account
func (c *HTTPClient) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1Register, &req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// VerifyEmail verifies a user's email address using the verification token
// The access token is automatically set on the client for subsequent authenticated requests
// Returns a LoginResponse with access token on successful verification
// May return MFAChallengeToken or MFASetupToken if user's role requires MFA
func (c *HTTPClient) VerifyEmail(ctx context.Context, req VerifyEmailRequest) (*LoginResponse, error) {
	var resp LoginResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1VerifyEmail, &req, &resp); err != nil {
		return nil, err
	}

	if resp.AccessToken != "" {
		c.accessToken = resp.AccessToken
	}

	return &resp, nil
}

// ForgotPassword initiates the password reset process
func (c *HTTPClient) ForgotPassword(ctx context.Context, req ForgotPasswordRequest) (*ForgotPasswordResponse, error) {
	var resp ForgotPasswordResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1ForgotPassword, &req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ResetPassword resets a user's password using the reset token
func (c *HTTPClient) ResetPassword(ctx context.Context, req ResetPasswordRequest) (*ResetPasswordResponse, error) {
	var resp ResetPasswordResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1ResetPassword, &req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OAuthLogin initiates an OAuth login flow
// Returns the authorization URL that the user should be redirected to
func (c *HTTPClient) OAuthLogin(ctx context.Context, req OIDCLoginRequest) (*OIDCAuthResponse, error) {
	var resp OIDCAuthResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1OAuthLogin, &req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SSOLogin initiates a corporate SSO login flow
// Returns the authorization URL that the user should be redirected to
func (c *HTTPClient) SSOLogin(ctx context.Context, req SSOLoginRequest) (*OIDCAuthResponse, error) {
	var resp OIDCAuthResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1SSOLogin, &req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListSupportedProviders returns the list of OAuth providers available for individual login
func (c *HTTPClient) ListSupportedProviders(ctx context.Context) (*OIDCProviderTypesResponse, error) {
	var resp OIDCProviderTypesResponse
	if err := c.doRequest(ctx, http.MethodGet, RouteV1OAuthSupportedTypes, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreateOIDCProvider creates a new OIDC provider configuration for corporate SSO
func (c *HTTPClient) CreateOIDCProvider(ctx context.Context, req CreateOIDCProviderRequest) (*OIDCProvider, error) {
	var provider OIDCProvider
	if err := c.doRequest(ctx, http.MethodPost, RouteV1OAuthProviders, &req, &provider); err != nil {
		return nil, err
	}
	return &provider, nil
}

// GetOIDCProvider retrieves an OIDC provider by ID
func (c *HTTPClient) GetOIDCProvider(ctx context.Context, req GetOIDCProviderRequest) (*OIDCProvider, error) {
	var provider OIDCProvider
	route := fmt.Sprintf("/v1/oauth/providers/%s", req.ProviderID.String())
	if err := c.doRequest(ctx, http.MethodGet, route, nil, &provider); err != nil {
		return nil, err
	}
	return &provider, nil
}

// ListOIDCProviders lists all OIDC providers for the tenant
func (c *HTTPClient) ListOIDCProviders(ctx context.Context) (*OIDCProvidersResponse, error) {
	var resp OIDCProvidersResponse
	if err := c.doRequest(ctx, http.MethodGet, RouteV1OAuthProviders, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateOIDCProvider updates an OIDC provider configuration
func (c *HTTPClient) UpdateOIDCProvider(ctx context.Context, req UpdateOIDCProviderRequest) (*OIDCProvider, error) {
	var provider OIDCProvider
	route := fmt.Sprintf("/v1/oauth/providers/%s", req.ProviderID.String())
	if err := c.doRequest(ctx, http.MethodPut, route, &req, &provider); err != nil {
		return nil, err
	}
	return &provider, nil
}

// DeleteOIDCProvider deletes an OIDC provider
func (c *HTTPClient) DeleteOIDCProvider(ctx context.Context, req DeleteOIDCProviderRequest) error {
	route := fmt.Sprintf("/v1/oauth/providers/%s", req.ProviderID.String())
	return c.doRequest(ctx, http.MethodDelete, route, nil, nil)
}

// RBAC - Permissions

// ListPermissions retrieves all system permissions
func (c *HTTPClient) ListPermissions(ctx context.Context) (*PermissionsResponse, error) {
	var resp PermissionsResponse
	if err := c.doRequest(ctx, http.MethodGet, RouteV1Permissions, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RBAC - Roles

// CreateRole creates a new role
func (c *HTTPClient) CreateRole(ctx context.Context, req CreateRoleRequest) (*Role, error) {
	var role Role
	if err := c.doRequest(ctx, http.MethodPost, RouteV1Roles, &req, &role); err != nil {
		return nil, err
	}
	return &role, nil
}

// GetRole retrieves a role by ID
func (c *HTTPClient) GetRole(ctx context.Context, req GetRoleRequest) (*Role, error) {
	var role Role
	route := fmt.Sprintf("/v1/roles/%s", req.RoleID.String())
	if err := c.doRequest(ctx, http.MethodGet, route, nil, &role); err != nil {
		return nil, err
	}
	return &role, nil
}

// ListRoles retrieves all roles for the tenant
func (c *HTTPClient) ListRoles(ctx context.Context) (*RolesResponse, error) {
	var resp RolesResponse
	if err := c.doRequest(ctx, http.MethodGet, RouteV1Roles, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateRole updates a role
func (c *HTTPClient) UpdateRole(ctx context.Context, req UpdateRoleRequest) (*Role, error) {
	var role Role
	route := fmt.Sprintf("/v1/roles/%s", req.RoleID.String())
	if err := c.doRequest(ctx, http.MethodPut, route, &req, &role); err != nil {
		return nil, err
	}
	return &role, nil
}

// DeleteRole deletes a role
func (c *HTTPClient) DeleteRole(ctx context.Context, req DeleteRoleRequest) error {
	route := fmt.Sprintf("/v1/roles/%s", req.RoleID.String())
	return c.doRequest(ctx, http.MethodDelete, route, nil, nil)
}

// RBAC - Role Permissions

// GetRolePermissions retrieves all permissions for a role
func (c *HTTPClient) GetRolePermissions(ctx context.Context, req GetRolePermissionsRequest) (*PermissionsResponse, error) {
	var resp PermissionsResponse
	route := fmt.Sprintf("/v1/roles/%s/permissions", req.RoleID.String())
	if err := c.doRequest(ctx, http.MethodGet, route, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SetRolePermissions sets all permissions for a role (bulk update)
func (c *HTTPClient) SetRolePermissions(ctx context.Context, req SetRolePermissionsRequest) error {
	route := fmt.Sprintf("/v1/roles/%s/permissions", req.RoleID.String())
	return c.doRequest(ctx, http.MethodPut, route, &req, nil)
}

// RBAC - User Roles

// GetUserRoles retrieves all roles for a user
func (c *HTTPClient) GetUserRoles(ctx context.Context, req GetUserRolesRequest) (*RolesResponse, error) {
	var resp RolesResponse
	route := fmt.Sprintf("/v1/users/%s/roles", req.UserID.String())
	if err := c.doRequest(ctx, http.MethodGet, route, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SetUserRoles sets all roles for a user
func (c *HTTPClient) SetUserRoles(ctx context.Context, req SetUserRolesRequest) error {
	route := fmt.Sprintf("/v1/users/%s/roles", req.UserID.String())
	return c.doRequest(ctx, http.MethodPut, route, &req, nil)
}

// RBAC - User Direct Permissions

// GetDirectPermissions retrieves direct permissions assigned to a user
func (c *HTTPClient) GetDirectPermissions(ctx context.Context, req GetDirectPermissionsRequest) (*DirectPermissionsResponse, error) {
	var resp DirectPermissionsResponse
	route := fmt.Sprintf("/v1/users/%s/permissions", req.UserID.String())
	if err := c.doRequest(ctx, http.MethodGet, route, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SetDirectPermissions sets all permissions for a user
func (c *HTTPClient) SetDirectPermissions(ctx context.Context, req SetDirectPermissionsRequest) error {
	route := fmt.Sprintf("/v1/users/%s/permissions", req.UserID.String())
	return c.doRequest(ctx, http.MethodPut, route, &req, nil)
}

// MFA - TOTP

// SetupMFA initiates MFA setup by generating TOTP secret, QR code, and backup codes
func (c *HTTPClient) SetupMFA(ctx context.Context) (*MFASetupResponse, error) {
	var resp MFASetupResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1MFASetup, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EnableMFA validates TOTP code and enables MFA
func (c *HTTPClient) EnableMFA(ctx context.Context, req EnableMFARequest) error {
	return c.doRequest(ctx, http.MethodPost, RouteV1MFAEnable, &req, nil)
}

// DisableMFA disables MFA for the authenticated user
func (c *HTTPClient) DisableMFA(ctx context.Context, req DisableMFARequest) error {
	return c.doRequest(ctx, http.MethodDelete, RouteV1MFADisable, &req, nil)
}

// GetMFAStatus retrieves MFA status for the authenticated user
func (c *HTTPClient) GetMFAStatus(ctx context.Context) (*MFAStatus, error) {
	var status MFAStatus
	if err := c.doRequest(ctx, http.MethodGet, RouteV1MFAStatus, nil, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// RegenerateBackupCodes generates new backup codes (requires password)
func (c *HTTPClient) RegenerateBackupCodes(ctx context.Context, req RegenerateBackupCodesRequest) (*BackupCodesResponse, error) {
	var resp BackupCodesResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1MFARegenerateCodes, &req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// VerifyMFACode verifies MFA code during login and completes authentication
// The access token is automatically set on the client for subsequent authenticated requests
func (c *HTTPClient) VerifyMFACode(ctx context.Context, req VerifyMFACodeRequest) (*LoginResponse, error) {
	var resp LoginResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1MFAVerify, &req, &resp); err != nil {
		return nil, err
	}

	c.accessToken = resp.AccessToken
	return &resp, nil
}

// RequiredMFASetup initiates MFA setup when a user's role requires MFA but they haven't set it up
// Returns the TOTP secret, QR code, and backup codes
func (c *HTTPClient) RequiredMFASetup(ctx context.Context, req RequiredMFASetupRequest) (*MFASetupResponse, error) {
	var resp MFASetupResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1MFARequiredSetup, &req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// RequiredMFAEnable enables MFA after required setup and issues an MFA challenge token
// After this succeeds, call VerifyMFACode to complete the login flow
func (c *HTTPClient) RequiredMFAEnable(ctx context.Context, req RequiredMFAEnableRequest) (*LoginResponse, error) {
	var resp LoginResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1MFARequiredEnable, &req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// Session Management

// ListSessions retrieves all active sessions for the authenticated user
func (c *HTTPClient) ListSessions(ctx context.Context) (*SessionsResponse, error) {
	var resp SessionsResponse
	if err := c.doRequest(ctx, http.MethodGet, RouteV1Sessions, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RevokeSession revokes a specific session by ID
func (c *HTTPClient) RevokeSession(ctx context.Context, req RevokeSessionRequest) error {
	route := fmt.Sprintf("/v1/sessions/%s", req.SessionID.String())
	return c.doRequest(ctx, http.MethodDelete, route, nil, nil)
}

// RevokeAllSessions revokes all sessions for the authenticated user (sign out everywhere)
func (c *HTTPClient) RevokeAllSessions(ctx context.Context) error {
	return c.doRequest(ctx, http.MethodDelete, RouteV1Sessions, nil, nil)
}

func (c *HTTPClient) doRequest(ctx context.Context, method, route string, req validatable, result any) error {
	var reqBody []byte = nil
	var err error

	if req != nil {
		if err := req.Validate(ctx); err != nil {
			return fmt.Errorf("invalid request: %w", err)
		}

		reqBody, err = json.Marshal(req)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
	}

	endpoint := fmt.Sprintf("%s%s", c.baseURL, route)

	httpReq, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if req != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	if c.accessToken != "" {
		httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
	}

	resp, err := c.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		// Drain and close to allow connection reuse
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// Check for error responses
	if resp.StatusCode >= 400 {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return &APIError{StatusCode: resp.StatusCode, Message: "failed to read error response"}
		}

		var errResp map[string]string
		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return &APIError{StatusCode: resp.StatusCode, Message: string(respBody)}
		}
		return &APIError{StatusCode: resp.StatusCode, Message: errResp["error"]}
	}

	// If no result expected (e.g., 204 No Content), return early
	if result == nil {
		return nil
	}

	// Read and decode success response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if err := json.Unmarshal(respBody, result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	return nil
}
