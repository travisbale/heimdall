package password

import (
	"context"
	"net/http"
	"testing"

	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/heimdall/test/_util/assertions"
	"github.com/travisbale/heimdall/test/_util/database"
	"github.com/travisbale/heimdall/test/_util/setup"
)

// A deactivated account keeps the password hash it was deactivated with, so knowing the
// password is not the question. The two statuses are refused differently on purpose:
// suspended is a real account being told no, while inactive is invisible to the lookup
// entirely and so answers exactly as an address nobody holds.
//
// Driven through the running service because the status the repository filters on and the
// status the domain checks are two separate rules, and a fake for either one agrees with
// whichever it was written against.
func TestLoginRefusesADeactivatedAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status string
		want   int
	}{
		{status: "suspended", want: http.StatusForbidden},
		{status: "inactive", want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			user := setup.CreateVerifiedUser(t, "deactivated-"+tt.status)
			database.SetUserStatus(t, user.Email, tt.status)

			_, err := setup.CreateClient(t).Login(context.Background(), sdk.LoginRequest{
				Email:    user.Email,
				Password: user.Password,
			})
			assertions.AssertAPIError(t, err, tt.want,
				"a "+tt.status+" account must be refused, not signed in")
		})
	}
}
