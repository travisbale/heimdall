package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// SessionsHandler handles session management HTTP requests
type SessionsHandler struct {
	sessionService sessionService
	authService    authService
	secureCookies  bool
}

// NewSessionsHandler creates a new SessionsHandler
func NewSessionsHandler(config *Config) *SessionsHandler {
	return &SessionsHandler{
		sessionService: config.SessionService,
		authService:    config.AuthService,
		secureCookies:  config.SecureCookies(),
	}
}

// ListSessions returns all active sessions for the authenticated user
func (h *SessionsHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := getAuthenticatedUserID(w, r)
	if !ok {
		return
	}

	sessions, err := h.sessionService.ListSessions(r.Context(), userID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to list sessions"})
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

	respondJSON(w, http.StatusOK, response)
}

// RevokeSession revokes a specific session by ID
func (h *SessionsHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID, ok := getAuthenticatedUserID(w, r)
	if !ok {
		return
	}

	sessionIDStr := chi.URLParam(r, "sessionID")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid session ID"})
		return
	}

	// Verify session belongs to user by listing their sessions first
	sessions, err := h.sessionService.ListSessions(r.Context(), userID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to verify session ownership"})
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
		respondJSON(w, http.StatusNotFound, sdk.ErrorResponse{Error: "Session not found"})
		return
	}

	if err := h.sessionService.RevokeSession(r.Context(), sessionID); err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to revoke session"})
		return
	}

	respondJSON(w, http.StatusOK, sdk.LogoutResponse{Message: "Session revoked"})
}

// RevokeAllSessions revokes all sessions for the authenticated user (sign out everywhere)
func (h *SessionsHandler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := getAuthenticatedUserID(w, r)
	if !ok {
		return
	}

	// Use AuthService to revoke sessions and trusted devices
	if err := h.authService.SignOutEverywhere(r.Context(), userID); err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to revoke sessions"})
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
		Secure:   h.secureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	// Clear device trust cookie
	http.SetCookie(w, &http.Cookie{
		Name:     deviceTrustCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	respondJSON(w, http.StatusOK, sdk.LogoutResponse{Message: "All sessions revoked"})
}
