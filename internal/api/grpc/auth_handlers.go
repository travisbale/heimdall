package grpc

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/internal/pb"
	"github.com/travisbale/heimdall/sdk"
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
	sdkReq := &sdk.CreateUserRequest{Email: req.Email}
	sdkReq.RoleIDs = make([]uuid.UUID, 0, len(req.RoleIds))
	for _, roleIDStr := range req.RoleIds {
		roleID, err := uuid.Parse(roleIDStr)
		if err != nil {
			return nil, fmt.Errorf("invalid role_id %s: %w", roleIDStr, err)
		}

		sdkReq.RoleIDs = append(sdkReq.RoleIDs, roleID)
	}

	if err := sdkReq.Validate(ctx); err != nil {
		return nil, err
	}

	user := &iam.User{Email: sdkReq.Email}
	user, verificationToken, err := h.AuthService.CreateUser(ctx, user, sdkReq.RoleIDs)
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
