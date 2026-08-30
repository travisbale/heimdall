// Package mailbox reads the tokens heimdall emailed, the same way a user would.
//
// Verification and password-reset tokens are stored hashed, so the database no longer
// holds anything a test can submit — which is the point of hashing them. The test stack
// uses the console email client, which logs each message as structured JSON, so the
// container log is the test suite's inbox.
package mailbox

import (
	"encoding/json"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	util "github.com/travisbale/heimdall/test/_util"
)

type emailLine struct {
	Msg             string `json:"msg"`
	Email           string `json:"email"`
	VerificationURL string `json:"verification_url"`
	ResetURL        string `json:"reset_url"`
}

// VerificationToken returns the token from the most recent verification email sent to
// this address.
func VerificationToken(t *testing.T, email string) string {
	t.Helper()
	return latestToken(t, email, func(l emailLine) string { return l.VerificationURL })
}

// PasswordResetToken returns the token from the most recent reset email sent to this
// address.
func PasswordResetToken(t *testing.T, email string) string {
	t.Helper()
	return latestToken(t, email, func(l emailLine) string { return l.ResetURL })
}

func latestToken(t *testing.T, email string, urlOf func(emailLine) string) string {
	t.Helper()

	out, err := exec.Command("docker", "logs", util.LoadConfig().HeimdallContainer).CombinedOutput()
	require.NoError(t, err, "failed to read %s logs (is the test stack running?)", util.LoadConfig().HeimdallContainer)

	// Last match wins: a test may request several tokens for one address.
	var found string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, email) {
			continue
		}
		var l emailLine
		if json.Unmarshal([]byte(line), &l) != nil || l.Email != email {
			continue
		}
		if raw := urlOf(l); raw != "" {
			u, err := url.Parse(raw)
			require.NoError(t, err, "unparseable email link %q", raw)
			if tok := u.Query().Get("token"); tok != "" {
				found = tok
			}
		}
	}

	require.NotEmpty(t, found, "no emailed token found for %s", email)
	return found
}
