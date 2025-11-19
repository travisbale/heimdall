package clog

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
)

// Helper to capture log output
func captureLog(fn func(logger *Logger)) map[string]any {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})

	// Set up default logger for the test
	slog.SetDefault(slog.New(handler))

	logger := New("test")

	fn(logger)

	var logEntry map[string]any
	json.Unmarshal(buf.Bytes(), &logEntry)
	return logEntry
}

func TestNew(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{})

	// Set up default logger for the test
	slog.SetDefault(slog.New(handler))

	logger := New("test_module")

	if logger == nil {
		t.Fatal("expected logger to be created")
	}

	// Verify module is set
	logger.Info(context.Background(), "test message")

	var logEntry map[string]any
	json.Unmarshal(buf.Bytes(), &logEntry)

	if logEntry[FieldModule] != "test_module" {
		t.Errorf("expected module to be 'test_module', got %v", logEntry[FieldModule])
	}
}

func TestLoggerInterface(t *testing.T) {
	// Verify Logger implements the logger interface
	var _ interface {
		Info(ctx context.Context, msg string, args ...any)
		Error(ctx context.Context, msg string, args ...any)
		Warn(ctx context.Context, msg string, args ...any)
	} = &Logger{}
}

func TestInfo(t *testing.T) {
	logEntry := captureLog(func(logger *Logger) {
		logger.Info(context.Background(), "test message", "key", "value")
	})

	if logEntry["msg"] != "test message" {
		t.Errorf("expected msg to be 'test message', got %v", logEntry["msg"])
	}
	if logEntry["key"] != "value" {
		t.Errorf("expected key to be 'value', got %v", logEntry["key"])
	}
	if logEntry["level"] != "INFO" {
		t.Errorf("expected level to be 'INFO', got %v", logEntry["level"])
	}
}

func TestError(t *testing.T) {
	logEntry := captureLog(func(logger *Logger) {
		logger.Error(context.Background(), "error message", "error", "something went wrong")
	})

	if logEntry["msg"] != "error message" {
		t.Errorf("expected msg to be 'error message', got %v", logEntry["msg"])
	}
	if logEntry["level"] != "ERROR" {
		t.Errorf("expected level to be 'ERROR', got %v", logEntry["level"])
	}
}

func TestWith(t *testing.T) {
	logEntry := captureLog(func(logger *Logger) {
		enrichedLogger := logger.With("request_id", "123")
		enrichedLogger.Info(context.Background(), "test message")
	})

	if logEntry["request_id"] != "123" {
		t.Errorf("expected request_id to be '123', got %v", logEntry["request_id"])
	}
}

func TestInfo_WithIdentity(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	ctx := identity.WithUser(context.Background(), userID, tenantID)

	logEntry := captureLog(func(logger *Logger) {
		logger.Info(ctx, "test message")
	})

	if logEntry[FieldUserID] != userID.String() {
		t.Errorf("expected user_id to be %v, got %v", userID, logEntry[FieldUserID])
	}
	if logEntry[FieldTenantID] != tenantID.String() {
		t.Errorf("expected tenant_id to be %v, got %v", tenantID, logEntry[FieldTenantID])
	}
}

func TestInfo_WithRequestID(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.RequestIDKey, "req-123")

	logEntry := captureLog(func(logger *Logger) {
		logger.Info(ctx, "test message")
	})

	if logEntry[FieldRequestID] != "req-123" {
		t.Errorf("expected request_id to be 'req-123', got %v", logEntry[FieldRequestID])
	}
}

func TestInfo_WithAllContext(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	ctx := identity.WithUser(context.Background(), userID, tenantID)
	ctx = context.WithValue(ctx, middleware.RequestIDKey, "req-456")

	logEntry := captureLog(func(logger *Logger) {
		logger.Info(ctx, "test message")
	})

	if logEntry[FieldUserID] != userID.String() {
		t.Errorf("expected user_id to be %v, got %v", userID, logEntry[FieldUserID])
	}
	if logEntry[FieldTenantID] != tenantID.String() {
		t.Errorf("expected tenant_id to be %v, got %v", tenantID, logEntry[FieldTenantID])
	}
	if logEntry[FieldRequestID] != "req-456" {
		t.Errorf("expected request_id to be 'req-456', got %v", logEntry[FieldRequestID])
	}
}

func TestInfo_EmptyContext(t *testing.T) {
	ctx := context.Background()

	logEntry := captureLog(func(logger *Logger) {
		logger.Info(ctx, "test message")
	})

	// Should not have user_id, tenant_id, or request_id
	if _, exists := logEntry[FieldUserID]; exists {
		t.Error("expected user_id to not be present")
	}
	if _, exists := logEntry[FieldTenantID]; exists {
		t.Error("expected tenant_id to not be present")
	}
	if _, exists := logEntry[FieldRequestID]; exists {
		t.Error("expected request_id to not be present")
	}
}
