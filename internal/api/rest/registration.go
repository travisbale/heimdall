package rest

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
)

// Register handles user registration (email only, password set during verification)
func (r *Router) register(w http.ResponseWriter, req *http.Request) {
	var body sdk.RegisterRequest
	if !r.decodeAndValidateJSON(w, req, &body) {
		return
	}

	user, err := r.UserService.Register(req.Context(), body.Email, body.FirstName, body.LastName)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrDuplicateEmail):
			r.writeError(req.Context(), w, http.StatusConflict, "Email address is already registered", err)

		case errors.Is(err, iam.ErrSSORequired):
			r.writeError(req.Context(), w, http.StatusBadRequest, "This email domain requires SSO login", err)

		default:
			r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to register user", err)
		}
		return
	}

	r.writeJSON(w, http.StatusCreated, sdk.RegisterResponse{
		UserID:  user.ID,
		Email:   user.Email,
		Message: "Registration successful. Please check your email to verify your account.",
	})
}

// ConfirmRegistration handles email verification, sets password, and returns JWT tokens for auto-login
func (r *Router) confirmRegistration(w http.ResponseWriter, req *http.Request) {
	var body sdk.VerifyEmailRequest
	if !r.decodeAndValidateJSON(w, req, &body) {
		return
	}

	tokens, err := r.AuthService.CompleteRegistration(req.Context(), body.Token, body.Password)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrVerificationTokenNotFound):
			r.writeError(req.Context(), w, http.StatusBadRequest, "Invalid or expired verification token", err)

		case errors.Is(err, iam.ErrAccountAlreadyVerified):
			r.writeError(req.Context(), w, http.StatusBadRequest, "Account has already been verified", err)

		default:
			r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to verify email", err)
		}
		return
	}

	r.encodeSessionResponse(w, req, tokens)
}
