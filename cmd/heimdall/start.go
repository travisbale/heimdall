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
		HTTPAddressFlag,
		GRPCAddressFlag,
		JWTPrivateKeyFlag,
		JWTPublicKeyFlag,
		JWTExpirationFlag,
		EnvironmentFlag,
		EmailLinkBaseURLFlag,
		MailmanGRPCAddressFlag,
		CORSAllowedOriginsFlag,
	},
	Action: func(c *cli.Context) error {
		// Create server config
		config := &app.Config{
			HTTPAddress:        c.String("http-address"),
			GRPCAddress:        c.String("grpc-address"),
			DatabaseURL:        c.String("database-url"),
			JWTPrivateKeyPath:  c.String("jwt-private-key"),
			JWTPublicKeyPath:   c.String("jwt-public-key"),
			JWTExpiration:      c.Duration("jwt-expiration"),
			BaseURL:            c.String("email-link-base-url"),
			MailmanGRPCAddress: c.String("mailman-grpc-address"),
			Environment:        c.String("environment"),
			CORSAllowedOrigins: c.StringSlice("cors-allowed-origins"),
			Logger:             slog.Default(),
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
