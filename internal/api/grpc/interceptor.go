package grpc

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/travisbale/knowhere/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Metadata header keys for identity propagation from API gateway
const (
	headerTenantID  = "x-tenant-id"
	headerActorID   = "x-actor-id"
	headerRequestID = "x-request-id"
	headerIPAddress = "x-ip-address"
)

// MetadataInterceptor extracts identity information from gRPC metadata headers
// and adds them to the request context. A tenant ID is required for every
// request; actor, request ID, and IP address are optional.
func MetadataInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, fmt.Errorf("missing gRPC metadata")
		}

		tenantVals := md.Get(headerTenantID)
		if len(tenantVals) == 0 {
			return nil, fmt.Errorf("tenant_id is required in metadata")
		}
		tenantID, err := uuid.Parse(tenantVals[0])
		if err != nil {
			return nil, fmt.Errorf("invalid tenant_id in metadata: %w", err)
		}

		// Attach actor if provided and parseable; fall back to tenant-only otherwise
		if actorVals := md.Get(headerActorID); len(actorVals) > 0 {
			if actorID, err := uuid.Parse(actorVals[0]); err == nil {
				ctx = identity.WithActor(ctx, tenantID, actorID)
			} else {
				ctx = identity.WithTenant(ctx, tenantID)
			}
		} else {
			ctx = identity.WithTenant(ctx, tenantID)
		}

		if vals := md.Get(headerRequestID); len(vals) > 0 && vals[0] != "" {
			ctx = identity.WithRequestID(ctx, vals[0])
		}
		if vals := md.Get(headerIPAddress); len(vals) > 0 && vals[0] != "" {
			ctx = identity.WithIPAddress(ctx, vals[0])
		}

		return handler(ctx, req)
	}
}
