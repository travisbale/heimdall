package password

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/request"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestGetMe(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "getme")
	ctx := context.Background()

	t.Run("returns user profile", func(t *testing.T) {
		me, err := user.Client.GetMe(ctx)
		require.NoError(t, err)
		assert.Equal(t, user.Email, me.Email)
		assert.Equal(t, "Test", me.FirstName)
		assert.Equal(t, "User", me.LastName)
		assert.Equal(t, "active", me.Status)
		assert.NotEmpty(t, me.ID)
		assert.NotEmpty(t, me.TenantID)
	})

	t.Run("unauthenticated request fails", func(t *testing.T) {
		status, _ := request.RawRequest(t, http.MethodGet, sdk.RouteV1Me, "", "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}
