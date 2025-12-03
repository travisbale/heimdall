package grpc

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/internal/pb"
	"github.com/travisbale/knowhere/identity"
)

// authService defines the interface for authentication operations
type authService interface {
	CreateUser(ctx context.Context, user *iam.User, roleIDs []uuid.UUID) (*iam.User, string, error)
}

type AuthHandler struct {
	pb.UnimplementedUserServiceServer
	AuthService authService
}

// CreateUser implements the gRPC CreateUser endpoint
func (h *AuthHandler) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}

	// Get tenant ID from context (set by MetadataInterceptor from gRPC metadata)
	tenantID, err := identity.GetTenant(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant_id is required in metadata")
	}

	var roleIDs []uuid.UUID
	for _, roleIDStr := range req.RoleIds {
		roleID, err := uuid.Parse(roleIDStr)
		if err != nil {
			return nil, fmt.Errorf("invalid role_id %s: %w", roleIDStr, err)
		}
		roleIDs = append(roleIDs, roleID)
	}

	user := &iam.User{
		TenantID: tenantID,
		Email:    req.Email,
	}

	user, verificationToken, err := h.AuthService.CreateUser(ctx, user, roleIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &pb.CreateUserResponse{
		UserId:            user.ID.String(),
		Email:             user.Email,
		TenantId:          user.TenantID.String(),
		VerificationToken: verificationToken,
	}, nil
}
