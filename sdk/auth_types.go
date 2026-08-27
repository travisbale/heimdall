package sdk

import (
	"context"

	"github.com/google/uuid"
)

// APIError is returned when the server responds with an HTTP error status code
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return e.Message
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type HealthResponse struct {
	Status string `json:"status"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Status    string    `json:"status"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (r *LoginRequest) Validate(ctx context.Context) error {
	if err := validateEmail(r.Email); err != nil {
		return err
	}
	return validateRequired(r.Password, "password")
}

// LoginResponse carries whichever the sign-in reached: an access token, or the challenge
// that has to be answered first. The refresh token is not in the body — it is set as an
// HTTP-only cookie, so script on the page cannot read it.
type LoginResponse struct {
	AccessToken       string `json:"access_token,omitempty"`        // Set when login is complete
	MFAChallengeToken string `json:"mfa_challenge_token,omitempty"` // Set when MFA verification is required
	MFASetupToken     string `json:"mfa_setup_token,omitempty"`     // Set when role requires MFA but user hasn't set it up
	TokenType         string `json:"token_type,omitempty"`          // "Bearer" for access tokens, omitted for challenge/setup tokens
	ExpiresIn         int    `json:"expires_in"`                    // Seconds until access token expires (OAuth 2.0 standard)
	RefreshExpiresIn  int    `json:"refresh_expires_in,omitempty"`  // Seconds until refresh token expires (extension to standard)
}

type LogoutResponse struct {
	Message string `json:"message"`
}

// CreateUserRequest creates a user. The tenant is not a field: it is the caller's own, read
// from gRPC metadata or a bearer token, so a caller cannot name one it does not hold.
type CreateUserRequest struct {
	Email   string      `json:"email"`
	RoleIDs []uuid.UUID `json:"role_ids,omitempty"` // Optional list of role IDs to assign
}

func (r *CreateUserRequest) Validate(ctx context.Context) error {
	return validateEmail(r.Email)
}

type CreateUserResponse struct {
	UserID            uuid.UUID `json:"user_id"`
	Email             string    `json:"email"`
	TenantID          uuid.UUID `json:"tenant_id"`
	VerificationToken string    `json:"verification_token"` // Empty for SSO users, set for non-SSO users
}

// RegisterRequest starts a registration. No password: one is set by following the emailed
// link, which is the step that proves the address belongs to whoever typed it.
type RegisterRequest struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

func (r *RegisterRequest) Validate(ctx context.Context) error {
	if err := validateEmail(r.Email); err != nil {
		return err
	}
	if err := validateRequired(r.FirstName, "first name"); err != nil {
		return err
	}
	return validateRequired(r.LastName, "last name")
}

type RegisterResponse struct {
	UserID  uuid.UUID `json:"user_id"`
	Email   string    `json:"email"`
	Message string    `json:"message"`
}

// VerifyEmailRequest completes a registration: it proves the address and sets the first
// password together.
type VerifyEmailRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (r *VerifyEmailRequest) Validate(ctx context.Context) error {
	if err := validateRequired(r.Token, "token"); err != nil {
		return err
	}
	if err := validateRequired(r.Password, "password"); err != nil {
		return err
	}
	return nil
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

func (r *ForgotPasswordRequest) Validate(ctx context.Context) error {
	return validateEmail(r.Email)
}

type ForgotPasswordResponse struct {
	Message string `json:"message"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (r *ResetPasswordRequest) Validate(ctx context.Context) error {
	if err := validateRequired(r.Token, "token"); err != nil {
		return err
	}
	if err := validateRequired(r.NewPassword, "new password"); err != nil {
		return err
	}
	return nil
}

type ResetPasswordResponse struct {
	Message string `json:"message"`
}
