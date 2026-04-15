package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	util "github.com/travisbale/heimdall/test/_util"
)

// CompleteOAuthFlow follows the OAuth authorization flow through the mock OIDC server,
// intercepts the frontend callback redirect, extracts the code and state,
// and calls the backend API directly. Returns the raw backend response.
func CompleteOAuthFlow(t *testing.T, authorizationURL string) *http.Response {
	t.Helper()

	// Intercept the redirect to the frontend callback URL (/oauth/callback)
	// since there's no frontend running in tests
	var callbackURL string
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Path == "/oauth/callback" {
				callbackURL = req.URL.String()
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}

	// The authorization URL contains the Docker-internal OIDC mock hostname, which isn't
	// resolvable from the host. Replace it with the host-accessible URL.
	config := util.LoadConfig()
	hostURL := strings.Replace(authorizationURL, config.OIDCMockInternalURL, config.OIDCMockURL, 1)

	resp, err := httpClient.Get(hostURL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.NotEmpty(t, callbackURL, "should have been redirected to callback URL")

	// Extract code and state, then call the backend directly
	parsed, err := url.Parse(callbackURL)
	require.NoError(t, err)
	code := parsed.Query().Get("code")
	state := parsed.Query().Get("state")
	require.NotEmpty(t, code, "callback should contain authorization code")
	require.NotEmpty(t, state, "callback should contain state")

	backendURL := fmt.Sprintf("%s%s?code=%s&state=%s",
		config.HeimdallBaseURL, sdk.RouteV1OAuthCallback,
		url.QueryEscape(code), url.QueryEscape(state))

	backendResp, err := http.Get(backendURL)
	require.NoError(t, err)

	return backendResp
}

// FollowOAuthFlow completes the OAuth flow and returns the parsed token response
func FollowOAuthFlow(t *testing.T, authorizationURL string) *sdk.LoginResponse {
	t.Helper()

	resp := CompleteOAuthFlow(t, authorizationURL)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode, "OAuth callback should return 200")

	var tokenResp sdk.LoginResponse
	err := json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err)

	return &tokenResp
}
