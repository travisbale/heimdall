package rest

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// ListSessions returns all active sessions for the authenticated user
func (r *Router) listSessions(w http.ResponseWriter, req *http.Request) {
	userID, ok := r.getAuthenticatedActorID(w, req)
	if !ok {
		return
	}

	sessions, err := r.SessionService.ListSessions(req.Context(), userID)
	if err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to list sessions", err)
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

	r.writeJSON(w, http.StatusOK, response)
}

// RevokeSession revokes a specific session by ID
func (r *Router) revokeSession(w http.ResponseWriter, req *http.Request) {
	userID, ok := r.getAuthenticatedActorID(w, req)
	if !ok {
		return
	}

	sessionID := parseUUID(req.PathValue("sessionID"))
	if sessionID == uuid.Nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, "Invalid session ID", nil)
		return
	}

	// Verify session belongs to user by listing their sessions first
	sessions, err := r.SessionService.ListSessions(req.Context(), userID)
	if err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to verify session ownership", err)
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
		r.writeError(req.Context(), w, http.StatusNotFound, "Session not found", nil)
		return
	}

	if err := r.SessionService.RevokeSession(req.Context(), sessionID); err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to revoke session", err)
		return
	}

	r.writeJSON(w, http.StatusOK, sdk.LogoutResponse{Message: "Session revoked"})
}

// RevokeAllSessions revokes all sessions for the authenticated user (sign out everywhere)
func (r *Router) revokeAllSessions(w http.ResponseWriter, req *http.Request) {
	userID, ok := r.getAuthenticatedActorID(w, req)
	if !ok {
		return
	}

	// Use AuthService to revoke sessions and trusted devices
	if err := r.AuthService.SignOutEverywhere(req.Context(), userID); err != nil {
		r.writeError(req.Context(), w, http.StatusInternalServerError, "Failed to revoke sessions", err)
		return
	}

	// Construct cookie path using X-Forwarded-Prefix if available
	prefix := req.Header.Get("X-Forwarded-Prefix")
	refreshCookiePath := prefix + sdk.RouteV1Refresh

	// Clear refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    "",
		Path:     refreshCookiePath,
		HttpOnly: true,
		Secure:   r.SecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	// Clear device trust cookie
	http.SetCookie(w, &http.Cookie{
		Name:     deviceTrustCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.SecureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	r.writeJSON(w, http.StatusOK, sdk.LogoutResponse{Message: "All sessions revoked"})
}
