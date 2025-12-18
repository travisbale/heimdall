package http

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
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
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	user, err := h.UserService.Register(r.Context(), req.Email, req.FirstName, req.LastName)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrDuplicateEmail):
			api.RespondError(w, http.StatusConflict, "Email address is already registered", err)

		case errors.Is(err, iam.ErrSSORequired):
			api.RespondError(w, http.StatusBadRequest, "This email domain requires SSO login", err)

		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to register user", err)
		}
		return
	}

	api.RespondJSON(w, http.StatusCreated, sdk.RegisterResponse{
		UserID:  user.ID,
		Email:   user.Email,
		Message: "Registration successful. Please check your email to verify your account.",
	})
}

// ConfirmRegistration handles email verification, sets password, and returns JWT tokens for auto-login
func (h *RegistrationHandler) ConfirmRegistration(w http.ResponseWriter, r *http.Request) {
	var req sdk.VerifyEmailRequest
	if !api.DecodeAndValidateJSON(w, r, &req) {
		return
	}

	tokens, err := h.AuthService.CompleteRegistration(r.Context(), req.Token, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrVerificationTokenNotFound):
			api.RespondError(w, http.StatusBadRequest, "Invalid or expired verification token", err)

		case errors.Is(err, iam.ErrAccountAlreadyVerified):
			api.RespondError(w, http.StatusBadRequest, "Account has already been verified", err)

		default:
			api.RespondError(w, http.StatusInternalServerError, "Failed to verify email", err)
		}
		return
	}

	encodeSessionResponse(w, r, tokens, h.SecureCookies)
}
