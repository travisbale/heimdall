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
	rbacService   rbacService
	jwtService    jwtService
	secureCookies bool // Secure flag prevents cookies from being sent over HTTP (only HTTPS)
}

// NewRegistrationHandler creates a new RegistrationHandler
func NewRegistrationHandler(config *Config) *RegistrationHandler {
	return &RegistrationHandler{
		userService:   config.UserService,
		rbacService:   config.RBACService,
		jwtService:    config.JWTService,
		secureCookies: config.SecureCookies(),
	}
}

// Register handles user registration (email only, password set during verification)
func (h *RegistrationHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req sdk.RegisterRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	user, err := h.userService.Register(r.Context(), req.Email)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrDuplicateEmail):
			respondJSON(w, http.StatusConflict, sdk.ErrorResponse{Error: "Email address is already registered"})

		case errors.Is(err, auth.ErrSSORequired):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "This email domain requires SSO login"})

		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to register user"})
		}
		return
	}

	respondJSON(w, http.StatusCreated, sdk.RegisterResponse{
		UserID:  user.ID,
		Email:   user.Email,
		Message: "Registration successful. Please check your email to verify your account.",
	})
}

// ConfirmRegistration handles email verification, sets password, and returns JWT tokens for auto-login
func (h *RegistrationHandler) ConfirmRegistration(w http.ResponseWriter, r *http.Request) {
	var req sdk.VerifyEmailRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	user, err := h.userService.ConfirmRegistration(r.Context(), req.Token, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrVerificationTokenNotFound):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid or expired verification token"})

		case errors.Is(err, auth.ErrAccountAlreadyVerified):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Account has already been verified"})

		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to verify email"})
		}
		return
	}

	// Auto-login after successful verification for better UX
	issueTokens(r.Context(), w, r, h.rbacService, h.jwtService, user.ID, user.TenantID, h.secureCookies)
}
