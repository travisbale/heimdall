package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

// RegistrationHandler handles user registration HTTP requests
type RegistrationHandler struct {
	userService   userService
	jwtService    jwtService
	secureCookies bool // Secure flag prevents cookies from being sent over HTTP (only HTTPS)
}

// NewRegistrationHandler creates a new RegistrationHandler
func NewRegistrationHandler(userService userService, jwtService jwtService, secureCookies bool) *RegistrationHandler {
	return &RegistrationHandler{
		userService:   userService,
		jwtService:    jwtService,
		secureCookies: secureCookies,
	}
}

// Register handles user registration
func (h *RegistrationHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req sdk.RegisterRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	user, err := h.userService.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrDuplicateEmail):
			respondError(w, http.StatusConflict, "Email address is already registered", err)

		case errors.Is(err, auth.ErrSSORequired):
			respondError(w, http.StatusBadRequest, "This email domain requires SSO login", err)

		default:
			respondError(w, http.StatusInternalServerError, "Failed to register user", err)
		}
		return
	}

	respondJSON(w, http.StatusCreated, sdk.RegisterResponse{
		UserID:  user.ID,
		Email:   user.Email,
		Message: "Registration successful. Please check your email to verify your account.",
	})
}

// ConfirmRegistration handles email verification and returns JWT tokens for auto-login
// Verifies token pre-authentication, then issues tokens to log user in immediately
func (h *RegistrationHandler) ConfirmRegistration(w http.ResponseWriter, r *http.Request) {
	var req sdk.VerifyEmailRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	user, err := h.userService.ConfirmRegistration(r.Context(), req.Token)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid or expired verification token", err)
		return
	}

	// Auto-login after successful verification for better UX
	issueTokens(r.Context(), w, r, h.userService, h.jwtService, user.ID, user.TenantID, h.secureCookies)
}

// ResendVerificationEmail handles resending the verification email
func (h *RegistrationHandler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var req sdk.ResendVerificationRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	err := h.userService.ResendVerificationEmail(r.Context(), req.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to resend verification email", err)
		return
	}

	// Always return success to prevent user enumeration attacks
	respondJSON(w, http.StatusOK, sdk.ResendVerificationResponse{
		Message: "If an unverified account exists with this email, a new verification email has been sent.",
	})
}
