package http

import (
	"net/http"

	"github.com/travisbale/heimdall/sdk"
)

// UserHandler handles user profile endpoints
type UserHandler struct {
	UserService userService
}

// GetMe retrieves the current authenticated user's profile
func (h *UserHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := getAuthenticatedActorID(w, r)
	if !ok {
		return
	}

	user, err := h.UserService.GetUser(r.Context(), userID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to retrieve user profile"})
		return
	}

	respondJSON(w, http.StatusOK, sdk.User{
		ID:        user.ID,
		TenantID:  user.TenantID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Status:    string(user.Status),
	})
}
