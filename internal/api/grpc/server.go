package grpc

import (
	"fmt"
	"net"

	"github.com/travisbale/heimdall/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Server implements the gRPC AuthService
type Server struct {
	Addr string
	*grpc.Server
}

// NewServer creates a new gRPC server
func NewServer(addr string, authService authService) *Server {
	grpcServer := grpc.NewServer()
	reflection.Register(grpcServer)

	authHandler := NewAuthHandler(authService)

	pb.RegisterUserServiceServer(grpcServer, authHandler)

	return &Server{
		Addr:   addr,
		Server: grpcServer,
	}
}

func (s *Server) ListenAndServe() error {
	// Create gRPC listener
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("failed to create gRPC listener: %w", err)
	}

	if err := s.Serve(listener); err != nil {
		fmt.Printf("gRPC server error: %v\n", err)
	}

	return nil
}
