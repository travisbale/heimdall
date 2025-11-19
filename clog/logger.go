package clog

import (
	"context"
	"log/slog"
)

// Logger wraps slog.Logger with automatic context enrichment
type Logger struct {
	base *slog.Logger
}

// New creates a new Logger with a module name using the default slog logger
func New(module string) *Logger {
	return &Logger{
		base: slog.Default().With(FieldModule, module),
	}
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
