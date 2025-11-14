package sdk

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
		config.dialOptions = append(config.dialOptions,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
	}

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

// CreateUser creates a new user for a tenant
func (c *GRPCClient) CreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResponse, error) {
	if err := req.Validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid request")
	}

	pbReq := &pb.CreateUserRequest{
		Email:    req.Email,
		TenantId: req.TenantID.String(),
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
		TemporaryPassword: pbResp.TemporaryPassword,
	}, nil
}
