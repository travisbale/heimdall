package isolation

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
)

func TestTenantIsolation_Sessions(t *testing.T) {
	t.Parallel()
	tenantA := createVerifiedUser(t, "iso-sessions-a")
	tenantB := createVerifiedUser(t, "iso-sessions-b")
	ctx := context.Background()

	t.Run("tenant B cannot see tenant A sessions", func(t *testing.T) {
		sessionsA, err := tenantA.Client.ListSessions(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, sessionsA.Sessions)

		sessionsB, err := tenantB.Client.ListSessions(ctx)
		require.NoError(t, err)

		// Tenant B's sessions should not contain tenant A's session IDs
		aIDs := make(map[uuid.UUID]bool)
		for _, s := range sessionsA.Sessions {
			aIDs[s.ID] = true
		}
		for _, s := range sessionsB.Sessions {
			assert.False(t, aIDs[s.ID], "tenant B should not see tenant A sessions")
		}
	})

	t.Run("tenant B cannot revoke tenant A session", func(t *testing.T) {
		sessionsA, err := tenantA.Client.ListSessions(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, sessionsA.Sessions)

		err = tenantB.Client.RevokeSession(ctx, sdk.RevokeSessionRequest{
			SessionID: sessionsA.Sessions[0].ID,
		})
		assert.Error(t, err, "tenant B should not revoke tenant A session")
	})
}
