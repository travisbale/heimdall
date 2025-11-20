package mailman

import (
	"context"
	"fmt"

	"github.com/travisbale/mailman/sdk"
)

const (
	verificationTemplateID  = "email-verification"
	passwordResetTemplateID = "password-reset"
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
	req := sdk.SendEmailRequest{
		TemplateID: verificationTemplateID,
		To:         emailAddress,
		Variables: map[string]string{
			"verification_url": fmt.Sprintf("%s/verify-email?token=%s", s.publicURL, token),
		},
	}

	_, err := s.client.SendEmail(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to send verification email via mailman: %w", err)
	}

	return nil
}

// SendPasswordResetEmail sends a password reset email via mailman
func (s *Client) SendPasswordResetEmail(ctx context.Context, emailAddress, token string) error {
	req := sdk.SendEmailRequest{
		TemplateID: passwordResetTemplateID,
		To:         emailAddress,
		Variables: map[string]string{
			"reset_url": fmt.Sprintf("%s/reset-password?token=%s", s.publicURL, token),
		},
	}

	_, err := s.client.SendEmail(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to send password reset email via mailman: %w", err)
	}

	return nil
}

// Close closes the gRPC connection to mailman
func (s *Client) Close() {
	_ = s.client.Close()
}
