package sdk

import (
	"fmt"

	"github.com/google/uuid"
)

type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate validates the login request
func (r *LoginRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	if r.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}

// LoginResponse represents the login response
// Note: refresh_token is sent via HTTP-only cookie, not in JSON body
type LoginResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"` // seconds until access token expires
}

// RefreshTokenResponse represents the refresh token response
type RefreshTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status string `json:"status"`
}

// CreateUserRequest represents the request to create a user
type CreateUserRequest struct {
	Email    string    `json:"email"`
	TenantID uuid.UUID `json:"tenant_id"`
}

// CreateUserResponse represents the response from creating a user
type CreateUserResponse struct {
	UserID            uuid.UUID `json:"user_id"`
	Email             string    `json:"email"`
	TenantID          uuid.UUID `json:"tenant_id"`
	TemporaryPassword string    `json:"temporary_password"`
}

// RegisterRequest represents the registration request body
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate validates the registration request
func (r *RegisterRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	if r.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(r.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	return nil
}

// RegisterResponse represents the registration response
type RegisterResponse struct {
	UserID  uuid.UUID `json:"user_id"`
	Email   string    `json:"email"`
	Message string    `json:"message"`
}

// ResendVerificationRequest represents the resend verification email request body
type ResendVerificationRequest struct {
	Email string `json:"email"`
}

// Validate validates the resend verification request
func (r *ResendVerificationRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	return nil
}

// ForgotPasswordRequest represents the forgot password request body
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// Validate validates the forgot password request
func (r *ForgotPasswordRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("email is required")
	}
	return nil
}

// ForgotPasswordResponse represents the forgot password response
type ForgotPasswordResponse struct {
	Message string `json:"message"`
}

// ResetPasswordRequest represents the reset password request body
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// Validate validates the reset password request
func (r *ResetPasswordRequest) Validate() error {
	if r.Token == "" {
		return fmt.Errorf("token is required")
	}
	if r.NewPassword == "" {
		return fmt.Errorf("new password is required")
	}
	if len(r.NewPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	return nil
}

// ResetPasswordResponse represents the reset password response
type ResetPasswordResponse struct {
	Message string `json:"message"`
}
