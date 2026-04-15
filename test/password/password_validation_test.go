package password

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/database"
	"github.com/travisbale/heimdall/test/_util/request"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestPasswordValidation(t *testing.T) {
	t.Parallel()
	client := setup.CreateClient(t)
	ctx := context.Background()

	email, _ := setup.GenerateTestCredentials(t, "passval")

	_, err := client.Register(ctx, sdk.RegisterRequest{
		Email:     email,
		FirstName: "Test",
		LastName:  "User",
	})
	require.NoError(t, err)

	token := database.GetVerificationToken(t, email)

	t.Run("reject short password", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1VerifyEmail,
			fmt.Sprintf(`{"token":"%s","password":"short"}`, token), "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, body, "password")
	})

	t.Run("accept valid password", func(t *testing.T) {
		_, err := client.VerifyEmail(ctx, sdk.VerifyEmailRequest{
			Token:    token,
			Password: fmt.Sprintf("ValidPass-%d!", time.Now().UnixNano()),
		})
		require.NoError(t, err)
	})
}
