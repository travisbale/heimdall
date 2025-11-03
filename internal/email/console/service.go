package console

import (
	"context"
	"fmt"
)

type logger interface {
	Info(msg string, args ...any)
}

// EmailService is a development implementation that logs emails to console
type EmailService struct {
	baseURL string
	logger  logger
}

// NewEmailService creates a new console email service
func NewEmailService(baseURL string, logger logger) *EmailService {
	return &EmailService{
		baseURL: baseURL,
		logger:  logger,
	}
}

// SendVerificationEmail logs the verification email to console
func (s *EmailService) SendVerificationEmail(ctx context.Context, email, token string) error {
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", s.baseURL, token)

	s.logger.Info("====== EMAIL VERIFICATION ======")
	s.logger.Info("To:", "email", email)
	s.logger.Info("Subject: Verify your email address")
	s.logger.Info("")
	s.logger.Info("Please click the link below to verify your email address:")
	s.logger.Info(verificationURL)
	s.logger.Info("")
	s.logger.Info("This link will expire in 24 hours.")
	s.logger.Info("================================")

	return nil
}
