package identity

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

type contextKey string

const (
	userIDContextKey   contextKey = "user_id"
	tenantIDContextKey contextKey = "tenant_id"
)

var ErrNoUserInContext = errors.New("no user ID found in context")
var ErrNoTenantInContext = errors.New("no tenant ID found in context")

// WithUser adds both user ID and tenant ID to the context
// Used by JWT middleware to propagate authenticated identity to handlers and database layer
func WithUser(ctx context.Context, userID, tenantID uuid.UUID) context.Context {
	ctx = context.WithValue(ctx, userIDContextKey, userID)
	ctx = context.WithValue(ctx, tenantIDContextKey, tenantID)
	return ctx
}

// GetUser retrieves the user ID from the context
func GetUser(ctx context.Context) (uuid.UUID, error) {
	userID, ok := ctx.Value(userIDContextKey).(uuid.UUID)
	if !ok || userID == uuid.Nil {
		return uuid.Nil, ErrNoUserInContext
	}
	return userID, nil
}

// GetTenant retrieves the tenant ID from the context
func GetTenant(ctx context.Context) (uuid.UUID, error) {
	tenantID, ok := ctx.Value(tenantIDContextKey).(uuid.UUID)
	if !ok || tenantID == uuid.Nil {
		return uuid.Nil, ErrNoTenantInContext
	}
	return tenantID, nil
}

// GetUserAndTenant retrieves both user ID and tenant ID from the context
func GetUserAndTenant(ctx context.Context) (userID, tenantID uuid.UUID, err error) {
	userID, err = GetUser(ctx)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	tenantID, err = GetTenant(ctx)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	return userID, tenantID, nil
}
