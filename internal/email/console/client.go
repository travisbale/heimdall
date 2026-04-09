// Package console provides an email client that logs email events to stdout.
// This is the default provider when no email configuration is set.
package console

import (
	"context"
	"log/slog"

	"github.com/travisbale/heimdall/internal/email"
)

// Client logs email events instead of sending them
type Client struct {
	logger    *slog.Logger
	publicURL string
}

// NewClient creates a new console email client
func NewClient(logger *slog.Logger, publicURL string) *Client {
	return &Client{logger: logger, publicURL: publicURL}
}

// SendVerificationEmail logs the verification token to stdout
func (c *Client) SendVerificationEmail(ctx context.Context, emailAddress, token string) error {
	c.logger.InfoContext(ctx, email.VerificationTemplate,
		"email", emailAddress,
		"verification_url", email.VerificationURL(c.publicURL, token),
	)
	return nil
}

// SendPasswordResetEmail logs the password reset token to stdout
func (c *Client) SendPasswordResetEmail(ctx context.Context, emailAddress, token string) error {
	c.logger.InfoContext(ctx, email.PasswordResetTemplate,
		"email", emailAddress,
		"reset_url", email.PasswordResetURL(c.publicURL, token),
	)
	return nil
}

// Close is a no-op for the console client
func (c *Client) Close() {}
