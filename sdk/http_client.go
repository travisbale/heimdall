package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// HTTPClient is an HTTP client for the heimdall API
type HTTPClient struct {
	baseURL    string
	httpClient *http.Client
	logger     logger
}

// NewHTTPClient creates a new heimdall API client
// The client automatically handles cookies for refresh token management
func NewHTTPClient(baseURL string, logger logger) (*HTTPClient, error) {
	// Create a cookie jar to automatically handle refresh token cookies
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	return &HTTPClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
		},
		logger: logger,
	}, nil
}

// WithHTTPClient allows setting a custom http.Client
// Note: If you provide a custom client for refresh token support,
// ensure it has a cookie jar configured
func (c *HTTPClient) WithHTTPClient(httpClient *http.Client) *HTTPClient {
	c.httpClient = httpClient
	return c
}

// Health checks the health of the heimdall API
func (c *HTTPClient) Health(ctx context.Context) (*HealthResponse, error) {
	endpoint := fmt.Sprintf("%s/healthz", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	var health HealthResponse
	if err := c.doRequest(req, &health); err != nil {
		return nil, err
	}

	return &health, nil
}

// Login authenticates a user and returns an access token
// The refresh token is automatically stored in the client's cookie jar
func (c *HTTPClient) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	endpoint := fmt.Sprintf("%s/v1/login", c.baseURL)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	var resp LoginResponse
	if err := c.doRequest(httpReq, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// Logout logs out the current user by clearing the refresh token cookie
func (c *HTTPClient) Logout(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/v1/logout", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	var resp map[string]string
	if err := c.doRequest(req, &resp); err != nil {
		return err
	}

	return nil
}

// RefreshToken refreshes the access token using the refresh token cookie
// The refresh token cookie must have been set by a previous Login call
func (c *HTTPClient) RefreshToken(ctx context.Context) (*RefreshTokenResponse, error) {
	endpoint := fmt.Sprintf("%s/v1/refresh", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	var resp RefreshTokenResponse
	if err := c.doRequest(req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// doRequest executes an HTTP request and decodes the response
func (c *HTTPClient) doRequest(req *http.Request, result any) error {
	resp, err := c.httpClient.Do(req)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for error responses
	if resp.StatusCode >= 400 {
		var errResp map[string]string
		if err := json.Unmarshal(body, &errResp); err != nil {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
		}
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, errResp["error"])
	}

	// Decode success response
	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	return nil
}
