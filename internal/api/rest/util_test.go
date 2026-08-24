package rest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func writeErrorFor(t *testing.T, status int, message string) (int, string) {
	t.Helper()
	// Discard the log: the point under test is what reaches the wire.
	router := &Router{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rec := httptest.NewRecorder()
	router.writeError(context.Background(), rec, status, message, errors.New("the database fell over"))

	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return rec.Code, body.Error
}

// A 4xx message is the caller's answer about their own request, so it is theirs to read.
func TestWriteErrorKeepsClientFacingMessages(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests} {
		code, got := writeErrorFor(t, status, "Incorrect email or password")
		if code != status || got != "Incorrect email or password" {
			t.Errorf("status %d: got %d %q, want the message unchanged", status, code, got)
		}
	}
}

// A fault is ours. Naming the operation tells the caller nothing they can act on, and
// reads as a verdict on their request — "Failed to verify email" sounds like a rejection
// of the address they sent.
func TestWriteErrorCollapsesEveryServerFault(t *testing.T) {
	for _, message := range []string{"Failed to verify email", "Failed to set role permissions", "Failed to revoke session"} {
		code, got := writeErrorFor(t, http.StatusInternalServerError, message)
		if code != http.StatusInternalServerError {
			t.Errorf("%q: got status %d", message, code)
		}
		if got != serverFault {
			t.Errorf("%q reached the client as %q, want the one fault message", message, got)
		}
	}

	if _, got := writeErrorFor(t, http.StatusBadGateway, "Upstream is down"); got != serverFault {
		t.Errorf("502 reached the client as %q, want the one fault message", got)
	}
}

// Registration and sign-in decode a body from anyone, so an unbounded one would stream
// straight into memory.
func TestDecodeJSONRejectsAnOversizedBody(t *testing.T) {
	body := `{"email":"` + strings.Repeat("a", maxRequestBody) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/login", strings.NewReader(body))
	rec := httptest.NewRecorder()

	var out map[string]any
	if err := decodeJSON(rec, req, &out); err == nil {
		t.Fatal("want a body over the cap to be refused, got no error")
	}
}

func TestDecodeJSONAcceptsABodyUnderTheCap(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/login", strings.NewReader(`{"email":"a@b.com"}`))
	rec := httptest.NewRecorder()

	var out map[string]any
	if err := decodeJSON(rec, req, &out); err != nil {
		t.Fatalf("want an ordinary body accepted, got %v", err)
	}
	if out["email"] != "a@b.com" {
		t.Errorf("decoded %v", out)
	}
}
