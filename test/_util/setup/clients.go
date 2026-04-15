package setup

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	util "github.com/travisbale/heimdall/test/_util"
)

// CreateClient returns a fresh unauthenticated HTTP client
func CreateClient(t *testing.T, opts ...sdk.Option) *sdk.HTTPClient {
	t.Helper()

	config := util.LoadConfig()
	client, err := sdk.NewHTTPClient(config.HeimdallBaseURL, opts...)
	require.NoError(t, err)

	return client
}

// CreateClientWithCookie creates an SDK client with a specific cookie set on the refresh path
func CreateClientWithCookie(t *testing.T, cookie *http.Cookie) *sdk.HTTPClient {
	t.Helper()

	config := util.LoadConfig()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	if cookie != nil {
		u, _ := url.Parse(config.HeimdallBaseURL)
		refreshURL := *u
		refreshURL.Path = sdk.RouteV1Refresh
		jar.SetCookies(&refreshURL, []*http.Cookie{cookie})
	}

	client, err := sdk.NewHTTPClient(config.HeimdallBaseURL, sdk.WithCookieJar(jar))
	require.NoError(t, err)

	return client
}

// FindRefreshCookie finds the refresh_token cookie in the jar
func FindRefreshCookie(t *testing.T, jar *cookiejar.Jar) *http.Cookie {
	t.Helper()

	config := util.LoadConfig()
	u, _ := url.Parse(config.HeimdallBaseURL + sdk.RouteV1Refresh)

	for _, c := range jar.Cookies(u) {
		if c.Name == "refresh_token" {
			return c
		}
	}

	t.Fatal("refresh_token cookie not found")
	return nil
}
