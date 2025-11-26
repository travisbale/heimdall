package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/clog"
	"github.com/travisbale/heimdall/identity"
)

// setupTestLogger initializes a JSON logger with context enrichment for testing
func setupTestLogger() (*bytes.Buffer, logger) {
	var buf bytes.Buffer
	jsonHandler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})
	contextHandler := clog.NewContextHandler(jsonHandler)
	slog.SetDefault(slog.New(contextHandler))
	return &buf, slog.Default()
}

// parseLogEntry parses the JSON log output from the buffer
func parseLogEntry(buf *bytes.Buffer) map[string]any {
	var logEntry map[string]any
	json.Unmarshal(buf.Bytes(), &logEntry)
	return logEntry
}

func TestLoggingMiddleware_Success(t *testing.T) {
	buf, logger := setupTestLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	wrappedHandler := Logger(logger)(handler)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	logEntry := parseLogEntry(buf)

	if logEntry["msg"] != RequestCompleted {
		t.Errorf("expected msg to be '%s', got %v", RequestCompleted, logEntry["msg"])
	}
	if logEntry["level"] != "INFO" {
		t.Errorf("expected level to be 'INFO', got %v", logEntry["level"])
	}
	if logEntry["http_method"] != "GET" {
		t.Errorf("expected http_method to be 'GET', got %v", logEntry["http_method"])
	}
	if logEntry["http_path"] != "/test" {
		t.Errorf("expected http_path to be '/test', got %v", logEntry["http_path"])
	}
	if logEntry["http_status"] != float64(200) {
		t.Errorf("expected http_status to be 200, got %v", logEntry["http_status"])
	}
	if _, exists := logEntry["duration_ms"]; !exists {
		t.Error("expected duration_ms to be present")
	}
}

func TestLoggingMiddleware_ClientError(t *testing.T) {
	buf, logger := setupTestLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	wrappedHandler := Logger(logger)(handler)
	req := httptest.NewRequest("GET", "/notfound", nil)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	logEntry := parseLogEntry(buf)

	if logEntry["level"] != "WARN" {
		t.Errorf("expected level to be 'WARN', got %v", logEntry["level"])
	}
	if logEntry["http_status"] != float64(404) {
		t.Errorf("expected http_status to be 404, got %v", logEntry["http_status"])
	}
}

func TestLoggingMiddleware_ServerError(t *testing.T) {
	buf, logger := setupTestLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	wrappedHandler := Logger(logger)(handler)
	req := httptest.NewRequest("POST", "/error", nil)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	logEntry := parseLogEntry(buf)

	if logEntry["level"] != "ERROR" {
		t.Errorf("expected level to be 'ERROR', got %v", logEntry["level"])
	}
	if logEntry["msg"] != RequestFailed {
		t.Errorf("expected msg to be '%s', got %v", RequestFailed, logEntry["msg"])
	}
	if logEntry["http_status"] != float64(500) {
		t.Errorf("expected http_status to be 500, got %v", logEntry["http_status"])
	}
}

func TestLoggingMiddleware_WithContext(t *testing.T) {
	buf, logger := setupTestLogger()

	userID := uuid.New()
	tenantID := uuid.New()
	ctx := identity.WithUser(context.Background(), userID, tenantID)
	ctx = identity.WithIPAddress(ctx, "192.168.1.100")
	ctx = context.WithValue(ctx, middleware.RequestIDKey, "req-123")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := Logger(logger)(handler)
	req := httptest.NewRequest("GET", "/api/users", nil)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	logEntry := parseLogEntry(buf)

	if logEntry["user_id"] != userID.String() {
		t.Errorf("expected user_id to be %v, got %v", userID, logEntry["user_id"])
	}
	if logEntry["tenant_id"] != tenantID.String() {
		t.Errorf("expected tenant_id to be %v, got %v", tenantID, logEntry["tenant_id"])
	}
	if logEntry["request_id"] != "req-123" {
		t.Errorf("expected request_id to be 'req-123', got %v", logEntry["request_id"])
	}
	if logEntry["ip_address"] != "192.168.1.100" {
		t.Errorf("expected ip_address to be '192.168.1.100', got %v", logEntry["ip_address"])
	}
}

func TestLoggingMiddleware_ImplicitStatusOK(t *testing.T) {
	buf, logger := setupTestLogger()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	wrappedHandler := Logger(logger)(handler)
	req := httptest.NewRequest("GET", "/implicit", nil)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	logEntry := parseLogEntry(buf)

	if logEntry["http_status"] != float64(200) {
		t.Errorf("expected http_status to be 200, got %v", logEntry["http_status"])
	}
	if logEntry["level"] != "INFO" {
		t.Errorf("expected level to be 'INFO', got %v", logEntry["level"])
	}
}
