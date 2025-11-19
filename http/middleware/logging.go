package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/travisbale/heimdall/clog"
)

// logger interface for HTTP request logging
type logger interface {
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}

// HTTP event constants for request logging
const (
	RequestCompleted = "request_completed"
	RequestFailed    = "request_failed"
)

// Logger returns middleware that logs HTTP requests with structured fields and context enrichment
// Automatically includes request_id, user_id, tenant_id, ip_address from context
func Logger(logger logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Process request
			next.ServeHTTP(ww, r)

			// Calculate duration
			duration := time.Since(start).Milliseconds()
			statusCode := ww.statusCode

			// Build log fields
			fields := []any{
				clog.FieldHTTPMethod, r.Method,
				clog.FieldHTTPPath, r.URL.Path,
				clog.FieldHTTPStatus, statusCode,
				clog.FieldDuration, duration,
			}

			// Log at appropriate level based on status code
			if statusCode >= 500 {
				// Server errors - log as ERROR
				logger.Error(r.Context(), RequestFailed, fields...)
			} else if statusCode >= 400 {
				// Client errors - log as WARN
				logger.Warn(r.Context(), RequestCompleted, fields...)
			} else {
				// Success - log as INFO
				logger.Info(r.Context(), RequestCompleted, fields...)
			}
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the status code before delegating to the underlying ResponseWriter
func (rw *responseWriter) WriteHeader(statusCode int) {
	if !rw.written {
		rw.statusCode = statusCode
		rw.written = true
		rw.ResponseWriter.WriteHeader(statusCode)
	}
}

// Write ensures WriteHeader is called if it hasn't been already
func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}
