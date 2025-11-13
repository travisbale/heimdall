package grpc

import (
	"fmt"
	"net"

	"github.com/travisbale/heimdall/internal/pb"
	"google.golang.org/grpc"
)

type Config struct {
	Addr        string
	AuthService authService
}

// Server implements gRPC UserService for internal service-to-service communication
type Server struct {
	Addr string
	*grpc.Server
}

func NewServer(config *Config) *Server {
	grpcServer := grpc.NewServer()

	authHandler := NewAuthHandler(config.AuthService)

	pb.RegisterUserServiceServer(grpcServer, authHandler)

	return &Server{
		Addr:   config.Addr,
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
