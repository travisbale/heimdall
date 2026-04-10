package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/travisbale/heimdall/internal/email"
)

func TestSendVerificationEmail(t *testing.T) {
	var received payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, http.MethodPost, r.Method)
		err := json.NewDecoder(r.Body).Decode(&received)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "https://app.example.com")
	err := client.SendVerificationEmail(context.Background(), "user@test.com", "token123")
	require.NoError(t, err)

	assert.Equal(t, email.VerificationTemplate, received.Template)
	assert.Equal(t, "user@test.com", received.Email)
	assert.Equal(t, "https://app.example.com/verify-email?token=token123", received.Variables["verification_url"])
}

func TestSendPasswordResetEmail(t *testing.T) {
	var received payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&received)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "https://app.example.com")
	err := client.SendPasswordResetEmail(context.Background(), "user@test.com", "reset456")
	require.NoError(t, err)

	assert.Equal(t, email.PasswordResetTemplate, received.Template)
	assert.Equal(t, "user@test.com", received.Email)
	assert.Equal(t, "https://app.example.com/reset-password?token=reset456", received.Variables["reset_url"])
}

func TestWebhookErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, "https://app.example.com")
	err := client.SendVerificationEmail(context.Background(), "user@test.com", "token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}
