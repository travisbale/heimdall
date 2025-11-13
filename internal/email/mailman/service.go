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

// EmailService sends emails via the mailman gRPC API
type EmailService struct {
	client    *sdk.GRPCClient
	publicURL string
}

// NewEmailService creates a new mailman email service
func NewEmailService(mailmanAddress, baseURL string) (*EmailService, error) {
	client, err := sdk.NewGRPCClient(mailmanAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mailman at %s: %w", mailmanAddress, err)
	}

	return &EmailService{
		client:    client,
		publicURL: baseURL,
	}, nil
}

// SendVerificationEmail sends a verification email via mailman
func (s *EmailService) SendVerificationEmail(ctx context.Context, email, token string) error {
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", s.publicURL, token)

	req := sdk.SendEmailRequest{
		TemplateID: verificationTemplateID,
		To:         email,
		Variables: map[string]string{
			"email":            email,
			"verification_url": verificationURL,
		},
	}

	_, err := s.client.SendEmail(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to send verification email via mailman: %w", err)
	}

	return nil
}

// SendPasswordResetEmail sends a password reset email via mailman
func (s *EmailService) SendPasswordResetEmail(ctx context.Context, email, token string) error {
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.publicURL, token)

	req := sdk.SendEmailRequest{
		TemplateID: passwordResetTemplateID,
		To:         email,
		Variables: map[string]string{
			"email":     email,
			"reset_url": resetURL,
		},
	}

	_, err := s.client.SendEmail(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to send password reset email via mailman: %w", err)
	}

	return nil
}

// Close closes the gRPC connection to mailman
func (s *EmailService) Close() {
	_ = s.client.Close()
}
