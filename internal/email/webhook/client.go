// Package webhook provides an email client that forwards email events
// to an external service via HTTP POST. The receiving service is responsible
// for composing and sending the actual email with appropriate branding.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/travisbale/heimdall/internal/email"
)

// Client sends email events to a webhook URL
type Client struct {
	url       string
	publicURL string
	http      *http.Client
}

// NewClient creates a new webhook email client
func NewClient(webhookURL, publicURL string) *Client {
	return &Client{
		url:       webhookURL,
		publicURL: publicURL,
		http:      &http.Client{},
	}
}

type payload struct {
	Template  string            `json:"template"`
	Email     string            `json:"email"`
	Variables map[string]string `json:"variables"`
}

// SendVerificationEmail posts a verification event to the webhook URL
func (c *Client) SendVerificationEmail(ctx context.Context, emailAddress, token string) error {
	return c.send(ctx, email.VerificationTemplate, emailAddress, map[string]string{
		"verification_url": email.VerificationURL(c.publicURL, token),
	})
}

// SendPasswordResetEmail posts a password reset event to the webhook URL
func (c *Client) SendPasswordResetEmail(ctx context.Context, emailAddress, token string) error {
	return c.send(ctx, email.PasswordResetTemplate, emailAddress, map[string]string{
		"reset_url": email.PasswordResetURL(c.publicURL, token),
	})
}

// Close is a no-op for the webhook client
func (c *Client) Close() {}

func (c *Client) send(ctx context.Context, template, emailAddress string, variables map[string]string) error {
	body, err := json.Marshal(&payload{
		Template:  template,
		Email:     emailAddress,
		Variables: variables,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
