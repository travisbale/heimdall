package http

import (
	"context"
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

type registrationService interface {
	Register(ctx context.Context, email, password string) (*auth.User, error)
	ConfirmRegistration(ctx context.Context, token string) error
}

// RegistrationHandler handles user registration HTTP requests
type RegistrationHandler struct {
	registrationService registrationService
}

// NewRegistrationHandler creates a new RegistrationHandler
func NewRegistrationHandler(registrationService registrationService) *RegistrationHandler {
	return &RegistrationHandler{
		registrationService: registrationService,
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

// ConfirmRegistration handles email verification
func (h *RegistrationHandler) ConfirmRegistration(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		respondError(w, http.StatusBadRequest, "Verification token is required", errors.New("missing token parameter"))
		return
	}

	err := h.registrationService.ConfirmRegistration(r.Context(), token)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid or expired verification token", err)
		return
	}

	// Return success response
	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Email verified successfully. You can now log in.",
	})
}
