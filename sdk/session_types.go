package sdk

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Session is one live sign-in: where it was started and when it was last used.
type Session struct {
	ID         uuid.UUID `json:"id"`
	UserAgent  string    `json:"user_agent"`
	IPAddress  string    `json:"ip_address"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

type SessionsResponse struct {
	Sessions []Session `json:"sessions"`
}

type RevokeSessionRequest struct {
	SessionID uuid.UUID `json:"-"` // From URL parameter
}

func (r *RevokeSessionRequest) Validate(ctx context.Context) error {
	return validateUUID(r.SessionID, "session_id")
}
