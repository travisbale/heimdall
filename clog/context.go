package clog

import (
	"context"
	"log/slog"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
)

// extractRequestID retrieves the request ID from chi middleware context
func extractRequestID(ctx context.Context) string {
	if reqID := middleware.GetReqID(ctx); reqID != "" {
		return reqID
	}
	return ""
}

// extractIdentity retrieves user_id and tenant_id from identity context
func extractIdentity(ctx context.Context) (userID, tenantID uuid.UUID, hasIdentity bool) {
	userID, tenantID, err := identity.GetUserAndTenant(ctx)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	return userID, tenantID, true
}

// enrichAttrs builds slog attributes from context and optional base attributes
func enrichAttrs(ctx context.Context, baseAttrs []slog.Attr) []slog.Attr {
	attrs := make([]slog.Attr, 0, len(baseAttrs)+4)

	// Add base attributes
	attrs = append(attrs, baseAttrs...)

	// Add request ID if available
	if reqID := extractRequestID(ctx); reqID != "" {
		attrs = append(attrs, slog.String(FieldRequestID, reqID))
	}

	// Add IP address if available
	if ipAddress := identity.GetIPAddress(ctx); ipAddress != "" {
		attrs = append(attrs, slog.String(FieldIPAddress, ipAddress))
	}

	// Add user and tenant IDs if available
	userID, tenantID, hasIdentity := extractIdentity(ctx)
	if hasIdentity {
		attrs = append(attrs,
			slog.String(FieldUserID, userID.String()),
			slog.String(FieldTenantID, tenantID.String()),
		)
	}

	return attrs
}
