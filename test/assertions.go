//go:build integration

package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// AssertHTTPError validates that an error contains the expected HTTP status code
func AssertHTTPError(t *testing.T, err error, statusCode, message string) {
	t.Helper()
	if !assert.Error(t, err, message) {
		return
	}
	assert.Contains(t, err.Error(), statusCode, "should return %s status", statusCode)
}

// AssertStatus400 validates input validation and malformed request handling
func AssertStatus400(t *testing.T, err error, message string) {
	t.Helper()
	AssertHTTPError(t, err, "400", message)
}

// AssertStatus401 validates authentication failures
func AssertStatus401(t *testing.T, err error, message string) {
	t.Helper()
	AssertHTTPError(t, err, "401", message)
}

// AssertStatus403 validates authorization and permission failures
func AssertStatus403(t *testing.T, err error, message string) {
	t.Helper()
	AssertHTTPError(t, err, "403", message)
}

// AssertStatus404 validates resource existence checks
func AssertStatus404(t *testing.T, err error, message string) {
	t.Helper()
	AssertHTTPError(t, err, "404", message)
}

// AssertStatus409 validates duplicate resource and state conflict detection
func AssertStatus409(t *testing.T, err error, message string) {
	t.Helper()
	AssertHTTPError(t, err, "409", message)
}

// AssertStatus429 validates rate limiting and account lockout
func AssertStatus429(t *testing.T, err error, message string) {
	t.Helper()
	AssertHTTPError(t, err, "429", message)
}
