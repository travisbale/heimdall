package assertions

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/travisbale/heimdall/sdk"
)

// AssertAPIError validates that an error is an APIError with the expected status code
func AssertAPIError(t *testing.T, err error, statusCode int, message string) {
	t.Helper()
	if !assert.Error(t, err, message) {
		return
	}
	apiErr, ok := errors.AsType[*sdk.APIError](err)
	if !assert.True(t, ok, "expected APIError, got: %T", err) {
		return
	}
	assert.Equal(t, statusCode, apiErr.StatusCode, message)
}
