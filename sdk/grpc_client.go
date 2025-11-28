package sdk

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/pb"
	"github.com/travisbale/knowhere/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// GRPCClient is a gRPC client for the heimdall API
type GRPCClient struct {
	conn   *grpc.ClientConn
	client pb.UserServiceClient
}

// GRPCClientOption is a functional option for configuring the gRPC client
type GRPCClientOption func(*grpcClientConfig)

type grpcClientConfig struct {
	dialOptions []grpc.DialOption
	timeout     time.Duration
}

// WithDialOptions allows setting custom gRPC dial options
func WithDialOptions(opts ...grpc.DialOption) GRPCClientOption {
	return func(c *grpcClientConfig) {
		c.dialOptions = append(c.dialOptions, opts...)
	}
}

// WithTimeout sets the default timeout for gRPC calls
func WithTimeout(timeout time.Duration) GRPCClientOption {
	return func(c *grpcClientConfig) {
		c.timeout = timeout
	}
}

// NewGRPCClient creates a new gRPC client for the heimdall API
// address should be in the format "host:port" (e.g., "localhost:9090")
func NewGRPCClient(address string, opts ...GRPCClientOption) (*GRPCClient, error) {
	config := &grpcClientConfig{
		timeout:     30 * time.Second,
		dialOptions: []grpc.DialOption{},
	}

	for _, opt := range opts {
		opt(config)
	}

	// Add default dial options if none provided
	if len(config.dialOptions) == 0 {
		config.dialOptions = append(config.dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Add identity propagation interceptor
	config.dialOptions = append(config.dialOptions,
		grpc.WithUnaryInterceptor(identityClientInterceptor()),
	)

	// Establish connection
	conn, err := grpc.NewClient(address, config.dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gRPC server: %w", err)
	}

	return &GRPCClient{
		conn:   conn,
		client: pb.NewUserServiceClient(conn),
	}, nil
}

// Close closes the gRPC connection
func (c *GRPCClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// identityClientInterceptor returns a client interceptor that automatically
// extracts identity information from the context and adds it to outgoing
// gRPC metadata. This propagates the authenticated user's identity to
// internal services without requiring explicit calls at each call site.
func identityClientInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		var pairs []string

		// Extract tenant and actor IDs from context
		if tenantID, err := identity.GetTenant(ctx); err == nil {
			pairs = append(pairs, "x-tenant-id", tenantID.String())
		}
		if actorID, err := identity.GetActor(ctx); err == nil {
			pairs = append(pairs, "x-actor-id", actorID.String())
		}

		// Extract request ID
		if reqID := identity.GetRequestID(ctx); reqID != "" {
			pairs = append(pairs, "x-request-id", reqID)
		}

		// Extract IP address
		if ipAddr := identity.GetIPAddress(ctx); ipAddr != "" {
			pairs = append(pairs, "x-ip-address", ipAddr)
		}

		// Add metadata to outgoing context if we have any identity info
		if len(pairs) > 0 {
			md := metadata.Pairs(pairs...)
			ctx = metadata.NewOutgoingContext(ctx, md)
		}

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// CreateUser creates a new user for a tenant
// Note: tenant_id is extracted from context and sent via gRPC metadata by the client interceptor
func (c *GRPCClient) CreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResponse, error) {
	if err := req.Validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid request")
	}

	// Convert role IDs to strings
	roleIDs := make([]string, len(req.RoleIDs))
	for i, roleID := range req.RoleIDs {
		roleIDs[i] = roleID.String()
	}

	pbReq := &pb.CreateUserRequest{
		Email:   req.Email,
		RoleIds: roleIDs,
	}

	pbResp, err := c.client.CreateUser(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	userID, err := uuid.Parse(pbResp.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user_id in response: %w", err)
	}

	tenantID, err := uuid.Parse(pbResp.TenantId)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id in response: %w", err)
	}

	return &CreateUserResponse{
		UserID:            userID,
		Email:             pbResp.Email,
		TenantID:          tenantID,
		VerificationToken: pbResp.VerificationToken,
	}, nil
}
