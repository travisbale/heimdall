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
	"strings"
	"time"
)

// validatable interface for requests that support validation
type validatable interface {
	Validate() error
}

// HTTPClient is an HTTP client for the heimdall API
type HTTPClient struct {
	baseURL     string
	httpClient  *http.Client
	logger      logger
	accessToken string
}

// Option is a functional option for configuring the HTTPClient
type Option func(*HTTPClient)

// WithHTTPClient allows setting a custom http.Client
// Note: If you provide a custom client for refresh token support,
// ensure it has a cookie jar configured
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *HTTPClient) {
		c.httpClient = httpClient
	}
}

// WithInsecureSkipVerify configures the client to skip TLS certificate verification
// This is useful for development with self-signed certificates
func WithInsecureSkipVerify() Option {
	return func(c *HTTPClient) {
		if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{}
			}
			transport.TLSClientConfig.InsecureSkipVerify = true
		}
	}
}

// NewHTTPClient creates a new heimdall API client
// The client automatically handles cookies for refresh token management
func NewHTTPClient(baseURL string, logger logger, opts ...Option) (*HTTPClient, error) {
	// Create a cookie jar to automatically handle refresh token cookies
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	client := &HTTPClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{},
			},
		},
		logger: logger,
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// SetAccessToken sets the access token for authenticated requests
func (c *HTTPClient) SetAccessToken(token string) {
	c.accessToken = token
}

// Health checks the health of the heimdall API
func (c *HTTPClient) Health(ctx context.Context) (*HealthResponse, error) {
	var resp HealthResponse
	if err := c.doRequest(ctx, http.MethodGet, RouteHealth, nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// Login authenticates a user and returns an access token
// The refresh token is automatically stored in the client's cookie jar
func (c *HTTPClient) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	var resp LoginResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1Login, &req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Logout logs out the current user by clearing the refresh token cookie
func (c *HTTPClient) Logout(ctx context.Context) (*LogoutResponse, error) {
	var resp LogoutResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1Logout, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RefreshToken refreshes the access token using the refresh token cookie
// The refresh token cookie must have been set by a previous Login call
func (c *HTTPClient) RefreshToken(ctx context.Context) (*LoginResponse, error) {
	var resp LoginResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1Refresh, nil, &resp); err != nil {
		return nil, err
	}
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
// Returns a LoginResponse with access token on successful verification
func (c *HTTPClient) VerifyEmail(ctx context.Context, req VerifyEmailRequest) (*LoginResponse, error) {
	var resp LoginResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1VerifyEmail, &req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ResendVerification resends the verification email to a user
func (c *HTTPClient) ResendVerification(ctx context.Context, req ResendVerificationRequest) (*ResendVerificationResponse, error) {
	var resp ResendVerificationResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1ResendVerification, &req, &resp); err != nil {
		return nil, err
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

// OAuthLink initiates an OAuth link flow to connect a provider to the authenticated user's account
// Requires a valid access token in the request context
// Returns the authorization URL that the user should be redirected to
func (c *HTTPClient) OAuthLink(ctx context.Context, req OIDCLinkRequest) (*OIDCAuthResponse, error) {
	var resp OIDCAuthResponse
	if err := c.doRequest(ctx, http.MethodPost, RouteV1OAuthLinks, &req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OAuthUnlinkProvider removes an OAuth provider link from the authenticated user's account
// Requires a valid access token in the request context
func (c *HTTPClient) OAuthUnlinkProvider(ctx context.Context, req OIDCUnlinkRequest) error {
	// Validate the request
	if err := req.Validate(); err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}

	// Build the URL path with the provider ID from the request
	route := strings.Replace(RouteV1OAuthLink, "{providerID}", req.ProviderID.String(), 1)
	// No response body for 204 No Content, no request body needed (provider ID is in URL)
	return c.doRequest(ctx, http.MethodDelete, route, nil, nil)
}

// OAuthListProviders lists all OAuth providers linked to the authenticated user's account
// Requires a valid access token in the request context
func (c *HTTPClient) OAuthListProviders(ctx context.Context) (*OIDCListLinksResponse, error) {
	var resp OIDCListLinksResponse
	if err := c.doRequest(ctx, http.MethodGet, RouteV1OAuthLinks, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *HTTPClient) doRequest(ctx context.Context, method, route string, req validatable, result any) error {
	var reqBody []byte = nil
	var err error

	if req != nil {
		if err := req.Validate(); err != nil {
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

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		// Drain and close to allow connection reuse
		_, _ = io.Copy(io.Discard, resp.Body)
		if err := resp.Body.Close(); err != nil {
			c.logger.Error("failed to close response body", "error", err)
		}
	}()

	// Check for error responses
	if resp.StatusCode >= 400 {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read error response: %w", err)
		}

		var errResp map[string]string
		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, errResp["error"])
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
