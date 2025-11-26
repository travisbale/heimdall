package sdk

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Session represents an active session in API responses
type Session struct {
	ID         uuid.UUID `json:"id"`
	UserAgent  string    `json:"user_agent"`
	IPAddress  string    `json:"ip_address"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// SessionsResponse represents the response with a list of sessions
type SessionsResponse struct {
	Sessions []Session `json:"sessions"`
}

// RevokeSessionRequest represents the request to revoke a specific session
type RevokeSessionRequest struct {
	SessionID uuid.UUID `json:"-"` // From URL parameter
}

// Validate validates the revoke session request
func (r *RevokeSessionRequest) Validate(ctx context.Context) error {
	return validateUUID(r.SessionID, "session_id")
}
