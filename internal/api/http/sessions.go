package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
)

// SessionsHandler handles session management HTTP requests
type SessionsHandler struct {
	SessionService sessionService
	AuthService    authService
	SecureCookies  bool
}

// ListSessions returns all active sessions for the authenticated user
func (h *SessionsHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := api.GetAuthenticatedActorID(w, r)
	if !ok {
		return
	}

	sessions, err := h.SessionService.ListSessions(r.Context(), userID)
	if err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to list sessions", err)
		return
	}

	response := sdk.SessionsResponse{
		Sessions: make([]sdk.Session, len(sessions)),
	}

	for i, s := range sessions {
		response.Sessions[i] = sdk.Session{
			ID:         s.ID,
			UserAgent:  s.UserAgent,
			IPAddress:  s.IPAddress,
			CreatedAt:  s.CreatedAt,
			LastUsedAt: s.LastUsedAt,
		}
	}

	api.RespondJSON(w, http.StatusOK, response)
}

// RevokeSession revokes a specific session by ID
func (h *SessionsHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID, ok := api.GetAuthenticatedActorID(w, r)
	if !ok {
		return
	}

	sessionIDStr := chi.URLParam(r, "sessionID")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		api.RespondError(w, http.StatusBadRequest, "Invalid session ID", err)
		return
	}

	// Verify session belongs to user by listing their sessions first
	sessions, err := h.SessionService.ListSessions(r.Context(), userID)
	if err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to verify session ownership", err)
		return
	}

	var found bool
	for _, s := range sessions {
		if s.ID == sessionID {
			found = true
			break
		}
	}

	if !found {
		api.RespondError(w, http.StatusNotFound, "Session not found", nil)
		return
	}

	if err := h.SessionService.RevokeSession(r.Context(), sessionID); err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to revoke session", err)
		return
	}

	api.RespondJSON(w, http.StatusOK, sdk.LogoutResponse{Message: "Session revoked"})
}

// RevokeAllSessions revokes all sessions for the authenticated user (sign out everywhere)
func (h *SessionsHandler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := api.GetAuthenticatedActorID(w, r)
	if !ok {
		return
	}

	// Use AuthService to revoke sessions and trusted devices
	if err := h.AuthService.SignOutEverywhere(r.Context(), userID); err != nil {
		api.RespondError(w, http.StatusInternalServerError, "Failed to revoke sessions", err)
		return
	}

	// Construct cookie path using X-Forwarded-Prefix if available
	prefix := r.Header.Get("X-Forwarded-Prefix")
	refreshCookiePath := prefix + sdk.RouteV1Refresh

	// Clear refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    "",
		Path:     refreshCookiePath,
		HttpOnly: true,
		Secure:   h.SecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	// Clear device trust cookie
	http.SetCookie(w, &http.Cookie{
		Name:     deviceTrustCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.SecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	api.RespondJSON(w, http.StatusOK, sdk.LogoutResponse{Message: "All sessions revoked"})
}
