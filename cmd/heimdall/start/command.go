package start

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/inconshreveable/log15"
	cli "github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
)

var Command = &cli.Command{
	Name:  "start",
	Usage: "Start the authentication service",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "ip",
			Aliases: []string{"i"},
			Usage:   "IP address for the server to listen on",
			Value:   "0.0.0.0",
			EnvVars: []string{"HEIMDALL_IP"},
		},
		&cli.IntFlag{
			Name:    "port",
			Aliases: []string{"p"},
			Usage:   "Port for the server to listen on",
			Value:   80,
			EnvVars: []string{"HEIMDALL_PORT"},
		},
	},

	Action: func(c *cli.Context) error {
		server, err := configureServer(c.String("ip"), c.Int("port"))
		if err != nil {
			return err
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		if err = startServer(ctx, server); err != nil {
			return err
		}

		return nil
	},
}

func configureServer(ip string, port int) (*http.Server, error) {
	return &http.Server{
		Addr: fmt.Sprintf("%s:%d", ip, port),
	}, nil
}

func startServer(ctx context.Context, server *http.Server) error {
	group, ctx := errgroup.WithContext(ctx)

	// Start the HTTP server
	group.Go(func() error {
		log15.Info(fmt.Sprintf("Listening on %s", server.Addr))
		return server.ListenAndServe()
	})

	// Shutdown gracefully
	group.Go(func() error {
		<-ctx.Done()
		log15.Info("Shutting down gracefully")
		return server.Shutdown(context.Background())
	})

	// Wait for the server to shutdown
	if err := group.Wait(); err != nil {
		return err
	}

	return nil
}
