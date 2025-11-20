package clog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
)

// Type aliases for slog types
type (
	Handler        = slog.Handler
	HandlerOptions = slog.HandlerOptions
	Level          = slog.Level
)

// Log levels
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Logger wraps slog.Logger with automatic context enrichment
type Logger struct {
	base *slog.Logger
}

// NewJSONHandler creates a handler that writes JSON logs to w
func NewJSONHandler(w io.Writer, opts *HandlerOptions) Handler {
	return slog.NewJSONHandler(w, opts)
}

// NewTextHandler creates a handler that writes text logs to w
func NewTextHandler(w io.Writer, opts *HandlerOptions) Handler {
	return slog.NewTextHandler(w, opts)
}

// SetDefault sets the default logger (used by New)
func SetDefault(h Handler) {
	slog.SetDefault(slog.New(h))
}

// InitDefault initializes the default logger to stderr (convenience method)
// format: "json" or "text"
// debug: if true, sets log level to Debug; otherwise Info
func InitDefault(format string, debug bool) error {
	var level Level
	if debug {
		level = LevelDebug
	} else {
		level = LevelInfo
	}

	var handler Handler
	switch format {
	case "json":
		handler = NewJSONHandler(os.Stderr, &HandlerOptions{Level: level})
	case "text":
		handler = NewTextHandler(os.Stderr, &HandlerOptions{Level: level})
	default:
		return fmt.Errorf("invalid log format %q: must be 'json' or 'text'", format)
	}

	SetDefault(handler)
	return nil
}

// New creates a new Logger with a module name using the default slog logger
func New(module string) *Logger {
	return &Logger{
		base: slog.Default().With(FieldModule, module),
	}
}

// Error logs an error using the default logger (convenience for rare infrastructure errors)
func Error(ctx context.Context, msg string, args ...any) {
	slog.Default().Error(msg, args...)
}

// Info logs at Info level with structured key-value pairs, automatically enriched with context
func (l *Logger) Info(ctx context.Context, msg string, args ...any) {
	attrs := enrichAttrs(ctx, nil)
	if len(attrs) > 0 {
		l.withAttrs(attrs...).base.Info(msg, args...)
	} else {
		l.base.Info(msg, args...)
	}
}

// Error logs at Error level with structured key-value pairs, automatically enriched with context
func (l *Logger) Error(ctx context.Context, msg string, args ...any) {
	attrs := enrichAttrs(ctx, nil)
	if len(attrs) > 0 {
		l.withAttrs(attrs...).base.Error(msg, args...)
	} else {
		l.base.Error(msg, args...)
	}
}

// Warn logs at Warn level with structured key-value pairs, automatically enriched with context
func (l *Logger) Warn(ctx context.Context, msg string, args ...any) {
	attrs := enrichAttrs(ctx, nil)
	if len(attrs) > 0 {
		l.withAttrs(attrs...).base.Warn(msg, args...)
	} else {
		l.base.Warn(msg, args...)
	}
}

// Debug logs at Debug level with structured key-value pairs, automatically enriched with context
func (l *Logger) Debug(ctx context.Context, msg string, args ...any) {
	attrs := enrichAttrs(ctx, nil)
	if len(attrs) > 0 {
		l.withAttrs(attrs...).base.Debug(msg, args...)
	} else {
		l.base.Debug(msg, args...)
	}
}

// With returns a new Logger with the given key-value pair added to all logs
func (l *Logger) With(args ...any) *Logger {
	return &Logger{
		base: l.base.With(args...),
	}
}

// withAttrs returns a new Logger with the given attributes added to all logs
func (l *Logger) withAttrs(attrs ...slog.Attr) *Logger {
	// Convert slog.Attr to []any for With() method
	args := make([]any, 0, len(attrs)*2)
	for _, attr := range attrs {
		args = append(args, attr.Key, attr.Value.Any())
	}
	return &Logger{
		base: l.base.With(args...),
	}
}
