package sdk

import (
	"context"

	"fmt"
	"github.com/google/uuid"
	"unicode/utf8"
)

// APIError is returned when the server responds with an HTTP error status code
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return e.Message
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// User represents a user in API responses
type User struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Status    string    `json:"status"`
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate validates the login request
func (r *LoginRequest) Validate(ctx context.Context) error {
	if err := validateEmail(r.Email); err != nil {
		return err
	}
	return validateRequired(r.Password, "password")
}

// LoginResponse represents the login response
// Note: refresh_token is sent via HTTP-only cookie, not in JSON body
type LoginResponse struct {
	AccessToken       string `json:"access_token,omitempty"`        // Set when login is complete
	MFAChallengeToken string `json:"mfa_challenge_token,omitempty"` // Set when MFA verification is required
	MFASetupToken     string `json:"mfa_setup_token,omitempty"`     // Set when role requires MFA but user hasn't set it up
	TokenType         string `json:"token_type,omitempty"`          // "Bearer" for access tokens, omitted for challenge/setup tokens
	ExpiresIn         int    `json:"expires_in"`                    // Seconds until access token expires (OAuth 2.0 standard)
	RefreshExpiresIn  int    `json:"refresh_expires_in,omitempty"`  // Seconds until refresh token expires (extension to standard)
}

// LogoutResponse represents the logout response
type LogoutResponse struct {
	Message string `json:"message"`
}

// CreateUserRequest represents the request to create a user
// Note: tenant_id is extracted from context and sent via gRPC metadata
type CreateUserRequest struct {
	Email   string      `json:"email"`
	RoleIDs []uuid.UUID `json:"role_ids,omitempty"` // Optional list of role IDs to assign
}

// Validate validates the create user request
func (r *CreateUserRequest) Validate(ctx context.Context) error {
	return validateEmail(r.Email)
}

// CreateUserResponse represents the response from creating a user
type CreateUserResponse struct {
	UserID            uuid.UUID `json:"user_id"`
	Email             string    `json:"email"`
	TenantID          uuid.UUID `json:"tenant_id"`
	VerificationToken string    `json:"verification_token"` // Empty for SSO users, set for non-SSO users
}

// Password length is part of the request contract, so a client can reject a bad one
// without a round trip. The minimum follows NIST guidance; the maximum bounds the work
// Argon2 is asked to do on an unauthenticated request.
//
// Whether a password is *guessable* is not here. That needs a word list and a lookup
// against a breach corpus, it can change for a password that has not, and it is the
// server's call — see internal/password.
const (
	MinPasswordLength = 10
	MaxPasswordLength = 128
)

// validatePasswordLength checks the one password property a client can check for itself.
func validatePasswordLength(password string) error {
	length := utf8.RuneCountInString(password)
	if length < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if length > MaxPasswordLength {
		return fmt.Errorf("password must not exceed %d characters", MaxPasswordLength)
	}
	return nil
}

// RegisterRequest represents the registration request body
// Password is set during email verification, not during initial registration
type RegisterRequest struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// Validate validates the registration request
func (r *RegisterRequest) Validate(ctx context.Context) error {
	if err := validateEmail(r.Email); err != nil {
		return err
	}
	if err := validateRequired(r.FirstName, "first name"); err != nil {
		return err
	}
	return validateRequired(r.LastName, "last name")
}

// RegisterResponse represents the registration response
type RegisterResponse struct {
	UserID  uuid.UUID `json:"user_id"`
	Email   string    `json:"email"`
	Message string    `json:"message"`
}

// VerifyEmailRequest represents the email verification request body
// User proves email ownership and sets their password
type VerifyEmailRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// Validate validates the verify email request
func (r *VerifyEmailRequest) Validate(ctx context.Context) error {
	if err := validateRequired(r.Token, "token"); err != nil {
		return err
	}
	if err := validateRequired(r.Password, "password"); err != nil {
		return err
	}
	return validatePasswordLength(r.Password)
}

// ForgotPasswordRequest represents the forgot password request body
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// Validate validates the forgot password request
func (r *ForgotPasswordRequest) Validate(ctx context.Context) error {
	return validateEmail(r.Email)
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
func (r *ResetPasswordRequest) Validate(ctx context.Context) error {
	if err := validateRequired(r.Token, "token"); err != nil {
		return err
	}
	if err := validateRequired(r.NewPassword, "new password"); err != nil {
		return err
	}
	return validatePasswordLength(r.NewPassword)
}

// ResetPasswordResponse represents the reset password response
type ResetPasswordResponse struct {
	Message string `json:"message"`
}
