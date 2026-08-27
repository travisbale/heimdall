package rest

import (
	"errors"
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
)

// GetMe retrieves the current authenticated user's profile
func (r *Router) getMe(w http.ResponseWriter, req *http.Request) {
	userID, ok := r.getAuthenticatedActorID(w, req)
	if !ok {
		return
	}

	user, err := r.UserService.GetUser(req.Context(), userID)
	if err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to retrieve user profile", err)
		return
	}

	r.writeJSON(w, http.StatusOK, sdk.User{
		ID:        user.ID,
		TenantID:  user.TenantID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Status:    string(user.Status),
	})
}

// createUser creates a user in the caller's tenant. Unlike registration it neither emails nor
// bootstraps a tenant: the verification token comes back in the response for the caller to
// deliver, which is what lets a service enrol its own people.
func (r *Router) createUser(w http.ResponseWriter, req *http.Request) {
	var body sdk.CreateUserRequest
	if !r.decodeAndValidateJSON(w, req, &body) {
		return
	}

	// No tenant is read off the request. It reaches the insert through the context the token
	// populated, and the row is placed by the policy in 001_init rather than by this handler.
	user, verificationToken, err := r.UserService.CreateUser(req.Context(), &iam.User{Email: body.Email}, body.RoleIDs)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrDuplicateEmail):
			r.writeError(req.Context(), w, http.StatusConflict, "Email address is already registered", err)

		case errors.Is(err, iam.ErrRoleNotFound):
			r.writeError(req.Context(), w, http.StatusBadRequest, "One of the roles does not exist", err)

		default:
			r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to create user", err)
		}
		return
	}

	r.writeJSON(w, http.StatusCreated, sdk.CreateUserResponse{
		UserID:            user.ID,
		Email:             user.Email,
		TenantID:          user.TenantID,
		VerificationToken: verificationToken,
	})
}
