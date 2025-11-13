package grpc

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/pb"
)

// authService defines the interface for authentication operations
type authService interface {
	CreateUser(ctx context.Context, tenantID uuid.UUID, email string) (*auth.User, string, error)
}

type AuthHandler struct {
	pb.UnimplementedUserServiceServer
	authService authService
}

func NewAuthHandler(authService authService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// CreateUser implements the gRPC CreateUser endpoint
func (h *AuthHandler) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if req.TenantId == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}

	tenantID, err := uuid.Parse(req.TenantId)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id: %w", err)
	}

	user, tempPassword, err := h.authService.CreateUser(ctx, tenantID, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &pb.CreateUserResponse{
		UserId:            user.ID.String(),
		Email:             user.Email,
		TenantId:          user.TenantID.String(),
		TemporaryPassword: tempPassword,
	}, nil
}
