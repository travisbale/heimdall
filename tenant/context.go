package tenant

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

type contextKey string

const tenantIDKey contextKey = "tenant_id"

// WithTenant adds tenant ID to context for RLS enforcement
func WithTenant(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

// FromContext extracts tenant ID from context
func FromContext(ctx context.Context) (uuid.UUID, error) {
	tenantID, ok := ctx.Value(tenantIDKey).(uuid.UUID)
	if !ok {
		return uuid.Nil, fmt.Errorf("tenant ID not found in context")
	}
	return tenantID, nil
}

// MustFromContext extracts tenant ID from context, panics if missing
// Use this in tests or when you're certain the context has been set
func MustFromContext(ctx context.Context) uuid.UUID {
	tenantID, err := FromContext(ctx)
	if err != nil {
		panic(err)
	}
	return tenantID
}
