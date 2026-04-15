package request

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	util "github.com/travisbale/heimdall/test/_util"
)

// RawRequest sends an HTTP request directly to the server, bypassing SDK client-side validation.
// Returns the response status code and body as a string.
func RawRequest(t *testing.T, method, path, body, accessToken string) (int, string) {
	t.Helper()

	config := util.LoadConfig()

	req, err := http.NewRequest(method, config.HeimdallBaseURL+path, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, string(respBody)
}
