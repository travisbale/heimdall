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
		DatabaseURLFlag,
		JWTPrivateKeyFlag,
		JWTPublicKeyFlag,
		JWTExpirationFlag,
		EnvironmentFlag,
		EmailLinkBaseURLFlag,
		MailmanGRPCAddressFlag,
		CORSAllowedOriginsFlag,
	},
	Action: func(c *cli.Context) error {
		// Convert CLI config to app config
		appConfig := config.ToAppConfig()

		// Create server with our API handlers
		server, err := app.NewServer(c.Context, appConfig)
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
