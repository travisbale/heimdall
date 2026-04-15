package rest

import (
	"net/http"

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
