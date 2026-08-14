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
	"github.com/travisbale/heimdall/test/_util/mailbox"
	"github.com/travisbale/heimdall/test/_util/request"
	"github.com/travisbale/heimdall/test/_util/setup"
	"strings"
)

// The strength check runs on the server, and only internal/app wires it up — the services
// skip it when no checker is configured. Every unit test still passes with that wiring
// removed, and so does TestPasswordValidation below, which only exercises length.
//
// So this is the test that fails if the checker is ever unwired: a password long enough to
// clear the request contract, but on the common list, has to be refused by the server.
// "qwertyuiop" is ten characters and hits the embedded list, so no network call is needed.
func TestPasswordStrengthIsEnforcedByTheServer(t *testing.T) {
	t.Parallel()
	client := setup.CreateClient(t)
	ctx := context.Background()

	email, _ := setup.GenerateTestCredentials(t, "passstrength")
	_, err := client.Register(ctx, sdk.RegisterRequest{
		Email:     email,
		FirstName: "Test",
		LastName:  "User",
	})
	require.NoError(t, err)

	token := mailbox.VerificationToken(t, email)

	// Sent raw rather than through the SDK, whose own Validate would pass it: the contract
	// checks length and nothing else, which is the point.
	status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1VerifyEmail,
		fmt.Sprintf(`{"token":"%s","password":"qwertyuiop"}`, token), "")

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body, "common")
}

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

	token := mailbox.VerificationToken(t, email)

	t.Run("reject short password", func(t *testing.T) {
		status, body := request.RawRequest(t, http.MethodPost, sdk.RouteV1VerifyEmail,
			fmt.Sprintf(`{"token":"%s","password":"short"}`, token), "")
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Contains(t, strings.ToLower(body), "password")
	})

	t.Run("accept valid password", func(t *testing.T) {
		_, err := client.VerifyEmail(ctx, sdk.VerifyEmailRequest{
			Token:    token,
			Password: fmt.Sprintf("ValidPass-%d!", time.Now().UnixNano()),
		})
		require.NoError(t, err)
	})
}
