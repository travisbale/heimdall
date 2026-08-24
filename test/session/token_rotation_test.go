package session

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/sdk"
	util "github.com/travisbale/heimdall/test/_util"
	"github.com/travisbale/heimdall/test/_util/setup"
)

// agentTransport stamps a User-Agent on every request, which is what separates the client a
// token was issued to from anyone else who has a copy of it.
type agentTransport struct {
	agent string
	base  http.RoundTripper
}

func (a *agentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", a.agent)
	return a.base.RoundTrip(req)
}

// clientPresenting builds a client offering the given cookie on the refresh path, under a user
// agent of its own. The jar comes back too, since a rotation lands the successor in it.
func clientPresenting(t *testing.T, cookie *http.Cookie, agent string) (*sdk.HTTPClient, *cookiejar.Jar) {
	t.Helper()

	config := util.LoadConfig()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	u, err := url.Parse(config.HeimdallBaseURL)
	require.NoError(t, err)
	refreshURL := *u
	refreshURL.Path = sdk.RouteV1Refresh
	jar.SetCookies(&refreshURL, []*http.Cookie{cookie})

	httpClient := &http.Client{
		Jar:       jar,
		Timeout:   30 * time.Second,
		Transport: &agentTransport{agent: agent, base: &http.Transport{TLSClientConfig: &tls.Config{}}},
	}

	client, err := sdk.NewHTTPClient(config.HeimdallBaseURL, sdk.WithHTTPClient(httpClient))
	require.NoError(t, err)

	return client, jar
}

func TestTokenRotation(t *testing.T) {
	t.Parallel()
	user, jar := setup.CreateVerifiedUserWithJar(t, "token-rotation")
	ctx := context.Background()

	t.Run("refresh rotates token", func(t *testing.T) {
		oldCookie := setup.FindRefreshCookie(t, jar)

		resp, err := user.Client.RefreshToken(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)

		// Old cookie should be different from the new one
		newCookie := setup.FindRefreshCookie(t, jar)
		assert.NotEqual(t, oldCookie.Value, newCookie.Value, "refresh token should rotate")
	})

	// A rotation whose response never arrived leaves the client holding a spent value.
	t.Run("the client that spent a token may present it again", func(t *testing.T) {
		const agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"

		// A token carries the agent it was issued to, so this client takes the session over first.
		client, ownJar := clientPresenting(t, setup.FindRefreshCookie(t, jar), agent)
		_, err := client.RefreshToken(ctx)
		require.NoError(t, err)

		// Spend it, keeping the value the way a client that never saw the answer would have.
		spent := setup.FindRefreshCookie(t, ownJar)
		_, err = client.RefreshToken(ctx)
		require.NoError(t, err)

		retry, _ := clientPresenting(t, spent, agent)
		_, err = retry.RefreshToken(ctx)
		assert.NoError(t, err, "the client that spent it must be able to ask again")
	})
}

func TestAReplayFromAnotherClientEndsTheSession(t *testing.T) {
	t.Parallel()
	user, jar := setup.CreateVerifiedUserWithJar(t, "token-replay")
	ctx := context.Background()

	spent := setup.FindRefreshCookie(t, jar)
	_, err := user.Client.RefreshToken(ctx)
	require.NoError(t, err)

	replay, _ := clientPresenting(t, spent, "curl/8.4.0")
	_, err = replay.RefreshToken(ctx)
	assert.Error(t, err, "a replay from another client should be refused")

	// Refused, and the family with it: the session the replayed token belonged to is gone.
	_, err = user.Client.RefreshToken(ctx)
	assert.Error(t, err, "detecting a replay should end the whole session")
}
