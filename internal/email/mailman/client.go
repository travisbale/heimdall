package mailman

import (
	"context"
	"fmt"

	"github.com/travisbale/heimdall/internal/email"
	"github.com/travisbale/mailman/sdk"
)

// Client sends emails via the mailman gRPC API
type Client struct {
	client    *sdk.GRPCClient
	publicURL string
}

// NewClient creates a new mailman email service
func NewClient(mailmanAddress, baseURL string) (*Client, error) {
	client, err := sdk.NewGRPCClient(mailmanAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mailman at %s: %w", mailmanAddress, err)
	}

	return &Client{
		client:    client,
		publicURL: baseURL,
	}, nil
}

// SendVerificationEmail sends a verification email via mailman
func (s *Client) SendVerificationEmail(ctx context.Context, emailAddress, token string) error {
	return s.send(ctx, email.VerificationTemplate, emailAddress, map[string]string{
		"verification_url": email.VerificationURL(s.publicURL, token),
	})
}

// SendPasswordResetEmail sends a password reset email via mailman
func (s *Client) SendPasswordResetEmail(ctx context.Context, emailAddress, token string) error {
	return s.send(ctx, email.PasswordResetTemplate, emailAddress, map[string]string{
		"reset_url": email.PasswordResetURL(s.publicURL, token),
	})
}

func (s *Client) send(ctx context.Context, templateID, emailAddress string, variables map[string]string) error {
	_, err := s.client.SendEmail(ctx, sdk.SendEmailRequest{
		TemplateID: templateID,
		To:         emailAddress,
		Variables:  variables,
	})
	if err != nil {
		return fmt.Errorf("failed to send email via mailman: %w", err)
	}
	return nil
}

// Close closes the gRPC connection to mailman
func (s *Client) Close() {
	_ = s.client.Close()
}
