package rest

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubDatabase struct{ err error }

func (d stubDatabase) Health(context.Context) error { return d.err }

func healthMux(t *testing.T, db database) http.Handler {
	t.Helper()
	router := &Router{DB: db, Environment: "test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	mux := http.NewServeMux()
	router.registerRoutes(mux)
	return mux
}

func TestHealthAnswersGet(t *testing.T) {
	rec := httptest.NewRecorder()
	healthMux(t, stubDatabase{}).ServeHTTP(rec, httptest.NewRequest("GET", "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got, want := strings.TrimSpace(rec.Body.String()), `{"status":"OK"}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

// The SDK client and the Dockerfile's healthcheck both probe with HEAD, so a GET route
// that stopped answering it would break them silently.
func TestHealthStillAnswersHead(t *testing.T) {
	rec := httptest.NewRecorder()
	healthMux(t, stubDatabase{}).ServeHTTP(rec, httptest.NewRequest("HEAD", "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHealthReportsAnUnreachableDatabase(t *testing.T) {
	rec := httptest.NewRecorder()
	db := stubDatabase{err: errors.New("connection refused")}
	healthMux(t, db).ServeHTTP(rec, httptest.NewRequest("GET", "/health", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}
