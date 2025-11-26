// Package clog provides a context-enriching handler for slog.
//
// Usage:
//
//	// Initialize once at startup
//	clog.Init("json", true) // or "text", debug=false
//
//	// Use slog directly throughout the codebase
//	slog.InfoContext(ctx, "user logged in", "email", email)
//
// The handler automatically extracts and adds to every log record:
//   - request_id (from chi middleware)
//   - ip_address (from identity context)
//   - user_id and tenant_id (from identity context)
package clog

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/travisbale/heimdall/identity"
)

// Init initializes the default slog logger with context enrichment.
// format: "json" or "text"
// debug: if true, sets log level to Debug; otherwise Info
func Init(format string, debug bool) error {
	var level slog.Level
	if debug {
		level = slog.LevelDebug
	} else {
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var baseHandler slog.Handler
	switch format {
	case "json":
		baseHandler = slog.NewJSONHandler(os.Stderr, opts)
	case "text":
		baseHandler = slog.NewTextHandler(os.Stderr, opts)
	default:
		return fmt.Errorf("invalid log format %q: must be 'json' or 'text'", format)
	}

	slog.SetDefault(slog.New(&contextHandler{inner: baseHandler}))
	return nil
}

// contextHandler wraps an slog.Handler to automatically enrich logs with context values
type contextHandler struct {
	inner slog.Handler
}

func (h *contextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if reqID := middleware.GetReqID(ctx); reqID != "" {
		r.AddAttrs(slog.String("request_id", reqID))
	}

	if ipAddress := identity.GetIPAddress(ctx); ipAddress != "" {
		r.AddAttrs(slog.String("ip_address", ipAddress))
	}

	if userID, tenantID, err := identity.GetUserAndTenant(ctx); err == nil {
		r.AddAttrs(
			slog.String("user_id", userID.String()),
			slog.String("tenant_id", tenantID.String()),
		)
	}

	return h.inner.Handle(ctx, r)
}

func (h *contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &contextHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *contextHandler) WithGroup(name string) slog.Handler {
	return &contextHandler{inner: h.inner.WithGroup(name)}
}

// NewContextHandler creates a context-enriching handler wrapping the given inner handler.
// Useful for tests that need context enrichment with a custom output destination.
func NewContextHandler(inner slog.Handler) slog.Handler {
	return &contextHandler{inner: inner}
}
