package password

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/assertions"
	"github.com/travisbale/heimdall/test/_util/database"
	"github.com/travisbale/heimdall/test/_util/setup"
)

func TestAccountLockout(t *testing.T) {
	t.Parallel()
	user := setup.CreateVerifiedUser(t, "lockout")
	client := setup.CreateClient(t)

	// Clear any prior login attempts
	database.ClearLoginAttempts(t, user.Email)

	t.Run("account locks after repeated failures", func(t *testing.T) {
		// Attempt 5 failed logins to trigger lockout
		for i := 0; i < 5; i++ {
			_, err := client.Login(context.Background(), sdk.LoginRequest{
				Email:    user.Email,
				Password: "WrongPassword123!",
			})
			assert.Error(t, err)
		}

		// Next attempt should be locked out
		_, err := client.Login(context.Background(), sdk.LoginRequest{
			Email:    user.Email,
			Password: user.Password,
		})
		assertions.AssertAPIError(t, err, http.StatusTooManyRequests, "account should be locked after 5 failed attempts")
	})
}
