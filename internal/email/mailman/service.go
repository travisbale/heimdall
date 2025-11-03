package mailman

import (
	"context"
	"fmt"

	"github.com/travisbale/mailman/sdk"
)

const (
	// verificationTemplateID is the template ID in mailman for email verification
	// Template must exist in mailman with variables: email, verification_url
	verificationTemplateID = "email-verification"

	// passwordResetTemplateID is the template ID in mailman for password reset
	// Template must exist in mailman with variables: email, reset_url
	passwordResetTemplateID = "password-reset"
)

// EmailService sends emails via the mailman gRPC API
type EmailService struct {
	client  *sdk.GRPCClient
	baseURL string
}

// NewEmailService creates a new mailman email service
func NewEmailService(client *sdk.GRPCClient, baseURL string) *EmailService {
	return &EmailService{
		client:  client,
		baseURL: baseURL,
	}
}

// SendVerificationEmail sends a verification email via mailman
func (s *EmailService) SendVerificationEmail(ctx context.Context, email, token string) error {
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", s.baseURL, token)

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
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.baseURL, token)

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
