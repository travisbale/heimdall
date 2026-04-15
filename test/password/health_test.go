package password

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestHealthCheck(t *testing.T) {
	t.Parallel()
	client := setup.CreateClient(t)

	err := client.Health(context.Background())
	require.NoError(t, err, "health check should succeed")
}
