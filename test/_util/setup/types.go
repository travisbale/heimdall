package setup

import (
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// UserClient holds an authenticated SDK client with user metadata
type UserClient struct {
	Client   *sdk.HTTPClient
	UserID   uuid.UUID
	TenantID uuid.UUID
	Email    string
	Password string
}
