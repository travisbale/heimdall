package http

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

type registrationService interface {
	Register(ctx context.Context, email, password string) (*auth.User, error)
	ConfirmRegistration(ctx context.Context, token string) (*auth.User, error)
	ResendVerificationEmail(ctx context.Context, email string) error
}

// RegistrationHandler handles user registration HTTP requests
type RegistrationHandler struct {
	registrationService registrationService
	userService         userService
	jwtService          jwtService
	secureCookies       bool          // Use Secure flag on cookies (HTTPS only)
	refreshExpiration   time.Duration // Refresh token expiration
}

// NewRegistrationHandler creates a new RegistrationHandler
func NewRegistrationHandler(registrationService registrationService, userService userService, jwtService jwtService, secureCookies bool, refreshExpiration time.Duration) *RegistrationHandler {
	return &RegistrationHandler{
		registrationService: registrationService,
		userService:         userService,
		jwtService:          jwtService,
		secureCookies:       secureCookies,
		refreshExpiration:   refreshExpiration,
	}
}

// Register handles user registration
func (h *RegistrationHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req sdk.RegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	user, err := h.registrationService.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		// Check for duplicate email error
		if errors.Is(err, auth.ErrDuplicateEmail) {
			respondError(w, http.StatusConflict, "Email address is already registered", err)
			return
		}

		respondError(w, http.StatusInternalServerError, "Failed to register user", err)
		return
	}

	respondJSON(w, http.StatusCreated, sdk.RegisterResponse{
		UserID:  user.ID,
		Email:   user.Email,
		Message: "Registration successful. Please check your email to verify your account.",
	})
}

// ConfirmRegistration handles email verification and returns JWT tokens for auto-login
func (h *RegistrationHandler) ConfirmRegistration(w http.ResponseWriter, r *http.Request) {
	var req sdk.VerifyEmailRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	user, err := h.registrationService.ConfirmRegistration(r.Context(), req.Token)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid or expired verification token", err)
		return
	}

	// Issue tokens and respond with access token
	issueTokensAndRespond(r.Context(), w, r, h.userService, h.jwtService, user.ID, user.TenantID, h.secureCookies, int(h.refreshExpiration.Seconds()))
}

// ResendVerificationEmail handles resending the verification email
func (h *RegistrationHandler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var req sdk.ResendVerificationRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := req.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error(), err)
		return
	}

	err := h.registrationService.ResendVerificationEmail(r.Context(), req.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to resend verification email", err)
		return
	}

	// Always return success to avoid user enumeration
	respondJSON(w, http.StatusOK, map[string]string{
		"message": "If an unverified account exists with this email, a new verification email has been sent.",
	})
}
