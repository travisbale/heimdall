package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
)

// RegistrationHandler handles user registration HTTP requests
type RegistrationHandler struct {
	UserService   userService
	AuthService   authService
	SecureCookies bool
}

// Register handles user registration (email only, password set during verification)
func (h *RegistrationHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req sdk.RegisterRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	user, err := h.UserService.Register(r.Context(), req.Email)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrDuplicateEmail):
			respondJSON(w, http.StatusConflict, sdk.ErrorResponse{Error: "Email address is already registered"})

		case errors.Is(err, iam.ErrSSORequired):
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

	tokens, err := h.AuthService.CompleteRegistration(r.Context(), req.Token, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrVerificationTokenNotFound):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid or expired verification token"})

		case errors.Is(err, iam.ErrAccountAlreadyVerified):
			respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Account has already been verified"})

		default:
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to verify email"})
		}
		return
	}

	encodeSessionResponse(w, r, tokens, h.SecureCookies)
}
