package postgres

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/test/_util/database"
	"github.com/travisbale/heimdall/test/_util/setup"
)

// container is the heimdall test container the cleanup command is run inside.
func container() string {
	if c := os.Getenv("HEIMDALL_TEST_CONTAINER"); c != "" {
		return c
	}
	return "heimdall-test"
}

func runCleanup(t *testing.T) {
	t.Helper()
	out, err := exec.Command("docker", "exec", container(), "./heimdall", "cleanup").CombinedOutput()
	require.NoError(t, err, "cleanup command failed: %s", out)
}

func count(t *testing.T, table, id string) int {
	t.Helper()
	var n int
	require.NoError(t, database.QueryRow(t,
		fmt.Sprintf("SELECT count(*) FROM %s WHERE id = $1", table), id).Scan(&n))
	return n
}

// Every table the cleanup touches is behind RLS, and a DELETE that matches nothing raises
// no error — so the command reports success whether or not it deleted anything. These
// assert the rows are gone rather than that the command exited zero.
//
// Seeded as the superuser, which is how a test reaches past RLS to put a row where the
// cleanup has to find it.
func TestCleanupDeletesExpiredRows(t *testing.T) {
	user := setup.CreateVerifiedUser(t, "cleanup")

	var tenantID, userID string
	require.NoError(t, database.QueryRow(t,
		"SELECT tenant_id::text, id::text FROM users WHERE email = $1", user.Email).Scan(&tenantID, &userID))

	refreshID := uuid.NewString()
	deviceID := uuid.NewString()

	database.Exec(t, `INSERT INTO refresh_tokens
		(id, tenant_id, user_id, token_hash, family_id, user_agent, ip_address, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, 'agent', '1.2.3.4', now() - interval '30 days', now() - interval '31 days')`,
		refreshID, tenantID, userID, "cleanup-"+refreshID, uuid.NewString())

	database.Exec(t, `INSERT INTO trusted_devices
		(id, tenant_id, user_id, token_hash, user_agent, ip_address, expires_at, created_at)
		VALUES ($1, $2, $3, $4, 'agent', '1.2.3.4', now() - interval '30 days', now() - interval '31 days')`,
		deviceID, tenantID, userID, "cleanup-"+deviceID)

	require.Equal(t, 1, count(t, "refresh_tokens", refreshID), "fixture did not land")
	require.Equal(t, 1, count(t, "trusted_devices", deviceID), "fixture did not land")

	runCleanup(t)

	require.Equal(t, 0, count(t, "refresh_tokens", refreshID), "expired refresh token survived the cleanup")
	require.Equal(t, 0, count(t, "trusted_devices", deviceID), "expired trusted device survived the cleanup")
}

// The unverified-user sweep is what keeps a spam registration from sitting in the table
// forever, and it is behind the same policy.
func TestCleanupDeletesOldUnverifiedUsers(t *testing.T) {
	tenantID := uuid.NewString()
	userID := uuid.NewString()

	database.Exec(t, "INSERT INTO tenants (id) VALUES ($1)", tenantID)
	database.Exec(t, `INSERT INTO users
		(id, tenant_id, email, password_hash, first_name, last_name, status, created_at)
		VALUES ($1, $2, $3, 'x', 'Old', 'User', 'unverified', now() - interval '60 days')`,
		userID, tenantID, "stale-"+userID+"@test.example.com")

	require.Equal(t, 1, count(t, "users", userID), "fixture did not land")

	runCleanup(t)

	require.Equal(t, 0, count(t, "users", userID), "old unverified user survived the cleanup")
}
