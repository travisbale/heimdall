package console

import (
	"context"
	"fmt"
)

type logger interface {
	Info(msg string, args ...any)
}

// EmailService logs emails to console for development (replace with SMTP for production)
type EmailService struct {
	publicURL string
	logger    logger
}

func NewEmailService(baseURL string, logger logger) *EmailService {
	return &EmailService{
		publicURL: baseURL,
		logger:    logger,
	}
}

// SendVerificationEmail logs verification email to console instead of sending
func (s *EmailService) SendVerificationEmail(ctx context.Context, email, token string) error {
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", s.publicURL, token)

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
