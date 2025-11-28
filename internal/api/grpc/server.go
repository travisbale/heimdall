package grpc

import (
	"context"
	"fmt"
	"net"

	"github.com/travisbale/heimdall/internal/pb"
	"google.golang.org/grpc"
)

// logger provides structured logging capabilities (matches *slog.Logger)
type logger interface {
	InfoContext(ctx context.Context, msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
	DebugContext(ctx context.Context, msg string, args ...any)
}

type Config struct {
	Addr        string
	AuthService authService
	Logger      logger
}

// Server implements gRPC UserService for internal service-to-service communication
type Server struct {
	Addr   string
	logger logger
	*grpc.Server
}

func NewServer(config *Config) *Server {
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(MetadataInterceptor()),
	)

	authHandler := NewAuthHandler(config.AuthService)

	pb.RegisterUserServiceServer(grpcServer, authHandler)

	return &Server{
		Addr:   config.Addr,
		logger: config.Logger,
		Server: grpcServer,
	}
}

func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("failed to create gRPC listener: %w", err)
	}

	if err := s.Serve(listener); err != nil {
		s.logger.ErrorContext(context.Background(), "gRPC server error", "error", err)
	}

	return nil
}
