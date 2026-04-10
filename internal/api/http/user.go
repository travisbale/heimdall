package http

import (
	"net/http"

	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
)

// GetMe retrieves the current authenticated user's profile
func (r *Router) getMe(w http.ResponseWriter, req *http.Request) {
	userID, ok := api.GetAuthenticatedActorID(w, req)
	if !ok {
		return
	}

	user, err := r.UserService.GetUser(req.Context(), userID)
	if err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to retrieve user profile", err)
		return
	}

	api.RespondJSON(w, http.StatusOK, sdk.User{
		ID:        user.ID,
		TenantID:  user.TenantID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Status:    string(user.Status),
	})
}
