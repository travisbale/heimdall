package oidc

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	util "github.com/travisbale/heimdall/test/_util"
	"github.com/travisbale/heimdall/test/_util/database"
	"github.com/travisbale/heimdall/test/_util/setup"
)

// ssoAccount is the identity the mock asserts. It is the same one whichever issuer is
// configured, so every SSO test in this package shares it.
//
// This test deactivates that account, which no test sharing it can tolerate, so it does not
// call t.Parallel — a package's serial tests all finish before its parallel ones resume —
// and it removes the account either side. Leaving it behind provisioned under this tenant is
// what makes the next test's auto-provision a 409 on an address it thought was free.
const ssoAccount = "mockuser@example.com"

// dropSSOAccount removes the shared account and, by cascade, the provider links onto it.
func dropSSOAccount(t *testing.T) {
	t.Helper()
	database.Exec(t, "DELETE FROM users WHERE email = $1", ssoAccount)
}

// Deactivating an account has to close every door into it, and SSO is a second door. The
// provider goes on asserting the identity — that is its job, and the status lives here, not
// there — so this side is the only one that can refuse.
func TestSSORefusesADeactivatedAccount(t *testing.T) {
	admin := setup.CreateAdminUser(t, "sso-deactivated")
	ctx := context.Background()
	config := util.LoadConfig()

	_, err := admin.Client.CreateOIDCProvider(ctx, sdk.CreateOIDCProviderRequest{
		ProviderName:             "Deactivation Corp SSO",
		IssuerURL:                config.OIDCMockInternalURL + "/default",
		ClientID:                 "test-client-id",
		ClientSecret:             "test-client-secret",
		Scopes:                   []string{"openid", "email", "profile"},
		Enabled:                  true,
		AllowedDomains:           []string{"deactivationcorp.com"},
		AutoCreateUsers:          true,
		RequireEmailVerification: false,
	})
	require.NoError(t, err)

	dropSSOAccount(t)
	t.Cleanup(func() { dropSSOAccount(t) })

	hint := fmt.Sprintf("leaver-%d@deactivationcorp.com", time.Now().UnixNano())

	authResp, err := admin.Client.SSOLogin(ctx, sdk.SSOLoginRequest{Email: hint})
	require.NoError(t, err)
	require.NotEmpty(t, FollowOAuthFlow(t, authResp.AuthorizationURL).AccessToken,
		"the account must sign in before deactivation, or the refusal below proves nothing")

	rows := database.ExecRows(t, "UPDATE users SET status = 'suspended' WHERE email = $1", ssoAccount)
	require.EqualValues(t, 1, rows, "the account the issuer asserts must be the one deactivated")

	authResp, err = admin.Client.SSOLogin(ctx, sdk.SSOLoginRequest{Email: hint})
	require.NoError(t, err)

	resp := CompleteOAuthFlow(t, authResp.AuthorizationURL)
	defer func() { _ = resp.Body.Close() }()

	assert.NotEqual(t, http.StatusOK, resp.StatusCode,
		"a suspended account must not be signed in through SSO")
}
