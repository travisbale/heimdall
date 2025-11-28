package grpc

import (
	"context"

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
// and adds them to the request context. This allows the API gateway to pass
// authenticated user information to internal services without re-validating JWTs.
func MetadataInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return handler(ctx, req)
		}

		// Extract tenant and actor IDs (set by API gateway after JWT validation)
		if vals := md.Get(headerTenantID); len(vals) > 0 {
			if tenantID, err := uuid.Parse(vals[0]); err == nil {
				if actorVals := md.Get(headerActorID); len(actorVals) > 0 {
					if actorID, err := uuid.Parse(actorVals[0]); err == nil {
						ctx = identity.WithActor(ctx, actorID, tenantID)
					}
				} else {
					ctx = identity.WithTenant(ctx, tenantID)
				}
			}
		}

		// Extract request ID for correlation
		if vals := md.Get(headerRequestID); len(vals) > 0 && vals[0] != "" {
			ctx = identity.WithRequestID(ctx, vals[0])
		}

		// Extract IP address for audit logging
		if vals := md.Get(headerIPAddress); len(vals) > 0 && vals[0] != "" {
			ctx = identity.WithIPAddress(ctx, vals[0])
		}

		return handler(ctx, req)
	}
}
