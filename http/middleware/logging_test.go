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

// setupTestLogger initializes a JSON logger for testing and returns the buffer and logger
func setupTestLogger() (*bytes.Buffer, logger) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})
	slog.SetDefault(slog.New(handler))
	logger := clog.New("http")
	return &buf, logger
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
	if logEntry[clog.FieldHTTPMethod] != "GET" {
		t.Errorf("expected http_method to be 'GET', got %v", logEntry[clog.FieldHTTPMethod])
	}
	if logEntry[clog.FieldHTTPPath] != "/test" {
		t.Errorf("expected http_path to be '/test', got %v", logEntry[clog.FieldHTTPPath])
	}
	if logEntry[clog.FieldHTTPStatus] != float64(200) {
		t.Errorf("expected http_status to be 200, got %v", logEntry[clog.FieldHTTPStatus])
	}
	if _, exists := logEntry[clog.FieldDuration]; !exists {
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
	if logEntry[clog.FieldHTTPStatus] != float64(404) {
		t.Errorf("expected http_status to be 404, got %v", logEntry[clog.FieldHTTPStatus])
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
	if logEntry[clog.FieldHTTPStatus] != float64(500) {
		t.Errorf("expected http_status to be 500, got %v", logEntry[clog.FieldHTTPStatus])
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

	if logEntry[clog.FieldUserID] != userID.String() {
		t.Errorf("expected user_id to be %v, got %v", userID, logEntry[clog.FieldUserID])
	}
	if logEntry[clog.FieldTenantID] != tenantID.String() {
		t.Errorf("expected tenant_id to be %v, got %v", tenantID, logEntry[clog.FieldTenantID])
	}
	if logEntry[clog.FieldRequestID] != "req-123" {
		t.Errorf("expected request_id to be 'req-123', got %v", logEntry[clog.FieldRequestID])
	}
	if logEntry[clog.FieldIPAddress] != "192.168.1.100" {
		t.Errorf("expected ip_address to be '192.168.1.100', got %v", logEntry[clog.FieldIPAddress])
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

	if logEntry[clog.FieldHTTPStatus] != float64(200) {
		t.Errorf("expected http_status to be 200, got %v", logEntry[clog.FieldHTTPStatus])
	}
	if logEntry["level"] != "INFO" {
		t.Errorf("expected level to be 'INFO', got %v", logEntry["level"])
	}
}
