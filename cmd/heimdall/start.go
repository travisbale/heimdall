package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/travisbale/heimdall/internal/app"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
)

var startCmd = &cli.Command{
	Name:  "start",
	Usage: "Start the HTTP API and gRPC service",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "database-url",
			Aliases: []string{"u"},
			Usage:   "PostgreSQL connection URL",
			Value:   "postgres://postgres:secure_password@postgres:5432/authsvc?sslmode=disable",
			EnvVars: []string{"DATABASE_URL"},
		},
		&cli.StringFlag{
			Name:    "http-address",
			Aliases: []string{"a"},
			Usage:   "HTTP address to listen on",
			Value:   ":8080",
			EnvVars: []string{"HTTP_ADDRESS"},
		},
		&cli.StringFlag{
			Name:    "grpc-address",
			Aliases: []string{"g"},
			Usage:   "gRPC address to listen on",
			Value:   ":9090",
			EnvVars: []string{"GRPC_ADDRESS"},
		},
		&cli.StringFlag{
			Name:     "jwt-private-key",
			Aliases:  []string{"k"},
			Usage:    "Path to JWT private key file (PEM format)",
			Required: true,
			EnvVars:  []string{"JWT_PRIVATE_KEY_PATH"},
		},
		&cli.StringFlag{
			Name:     "jwt-public-key",
			Aliases:  []string{"p"},
			Usage:    "Path to JWT public key file (PEM format)",
			Required: true,
			EnvVars:  []string{"JWT_PUBLIC_KEY_PATH"},
		},
		&cli.DurationFlag{
			Name:    "jwt-expiration",
			Aliases: []string{"x"},
			Usage:   "JWT token expiration duration",
			Value:   24 * time.Hour,
			EnvVars: []string{"JWT_EXPIRATION"},
		},
		&cli.StringFlag{
			Name:    "environment",
			Aliases: []string{"e"},
			Usage:   "Environment (development, staging, production)",
			Value:   "development",
			EnvVars: []string{"ENVIRONMENT"},
		},
		&cli.StringFlag{
			Name:    "base-url",
			Aliases: []string{"b"},
			Usage:   "Base URL for email verification links",
			Value:   "http://localhost:8080",
			EnvVars: []string{"BASE_URL"},
		},
	},
	Action: func(c *cli.Context) error {
		// Create server config
		config := &app.Config{
			HTTPAddress:       c.String("http-address"),
			GRPCAddress:       c.String("grpc-address"),
			DatabaseURL:       c.String("database-url"),
			JWTPrivateKeyPath: c.String("jwt-private-key"),
			JWTPublicKeyPath:  c.String("jwt-public-key"),
			JWTExpiration:     c.Duration("jwt-expiration"),
			BaseURL:           c.String("base-url"),
			Environment:       c.String("environment"),
			Logger:            slog.Default(),
		}

		// Create server with our API handlers
		server, err := app.NewServer(c.Context, config)
		if err != nil {
			return err
		}

		httpAddr := config.HTTPAddress
		grpcAddr := config.GRPCAddress

		ctx, cancel := signal.NotifyContext(c.Context, os.Interrupt, syscall.SIGTERM)
		defer cancel()

		group, ctx := errgroup.WithContext(ctx)

		// Start servers
		group.Go(func() error {
			slog.Info("Listening for connections", "http_address", httpAddr, "grpc_address", grpcAddr)
			return server.Start()
		})

		// Handle shutdown
		group.Go(func() error {
			<-ctx.Done()
			slog.Info("Shutting down gracefully")

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			return server.Shutdown(shutdownCtx)
		})

		if err := group.Wait(); err != nil && err != context.Canceled {
			return err
		}

		return nil
	},
}
