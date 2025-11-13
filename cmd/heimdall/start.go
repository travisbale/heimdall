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
	Usage: "Start HTTP and gRPC servers with graceful shutdown",
	Flags: []cli.Flag{
		HTTPAddressFlag,
		GRPCAddressFlag,
		DatabaseURLFlag,
		JWTIssuerFlag,
		JWTPrivateKeyFlag,
		JWTPublicKeyFlag,
		JWTExpirationFlag,
		EnvironmentFlag,
		PublicURLFlag,
		MailmanGRPCAddressFlag,
		EncryptionKeyFlag,
		CORSAllowedOriginsFlag,
	},
	Action: func(c *cli.Context) error {
		appConfig := config.ToAppConfig()

		server, err := app.NewServer(c.Context, appConfig)
		if err != nil {
			return err
		}

		httpAddr := config.HTTPAddress
		grpcAddr := config.GRPCAddress

		// Trap SIGINT/SIGTERM for graceful shutdown
		ctx, cancel := signal.NotifyContext(c.Context, os.Interrupt, syscall.SIGTERM)
		defer cancel()

		group, ctx := errgroup.WithContext(ctx)

		group.Go(func() error {
			slog.Info("Listening for connections", "http_address", httpAddr, "grpc_address", grpcAddr)
			return server.Start()
		})

		// Wait for signal, then gracefully shutdown with 10s timeout
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
