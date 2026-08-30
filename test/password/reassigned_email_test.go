package password

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/database"
	"github.com/travisbale/heimdall/test/_util/setup"
)

// The unique index on email is partial — only active rows are constrained — so a deactivated
// row and a live one can hold the same address at once. That is what it is for: an address
// is handed to whoever holds the job now.
//
// The old row is deactivated first and the live one added after it, which is the order a
// reassignment actually happens in, and the order that decides which row an unordered lookup
// reaches first. Both carry the same hash, so the password cannot be what decides: a refusal
// here means the lookup answered with the row that is no longer anybody.
func TestLoginResolvesToTheLiveAccountWhenAnAddressWasReassigned(t *testing.T) {
	t.Parallel()

	former := setup.CreateVerifiedUser(t, "reassigned")

	var hash, tenantID string
	require.NoError(t, database.QueryRow(t,
		"SELECT password_hash, tenant_id::text FROM users WHERE email = $1", former.Email).Scan(&hash, &tenantID))

	database.SetUserStatus(t, former.Email, "suspended")

	database.Exec(t, `INSERT INTO users
		(id, tenant_id, email, password_hash, first_name, last_name, status)
		VALUES ($1, $2, $3, $4, 'New', 'Hire', 'active')`,
		uuid.NewString(), tenantID, former.Email, hash)

	_, err := setup.CreateClient(t).Login(context.Background(), sdk.LoginRequest{
		Email:    former.Email,
		Password: former.Password,
	})
	require.NoError(t, err, "the live account holding this address must be the one that signs in")
}
