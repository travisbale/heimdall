package start

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/inconshreveable/log15"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/travisbale/heimdall/internal/api/http/gin"
	"github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/travisbale/heimdall/internal/heimdall"
	"github.com/travisbale/heimdall/internal/lib/argon2"
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
		},
		&cli.IntFlag{
			Name:    "port",
			Aliases: []string{"p"},
			Usage:   "Port for the server to listen on",
			Value:   5000,
		},
		&cli.StringFlag{
			Name:    "db-url",
			Usage:   "Database connection string",
			EnvVars: []string{"DATABASE_URL"},
		},
	},

	Action: func(c *cli.Context) error {
		// Create a cancel context to gracefully shutdown the application
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		// Open the database connection pool
		connectionPool, err := pgxpool.New(ctx, c.String("db-url"))
		if err != nil {
			return err
		}
		defer connectionPool.Close()

		// Configure the HTTP server
		server, err := configureServer(ctx, c.String("ip"), c.Int("port"), connectionPool)
		if err != nil {
			return err
		}

		// Start listening for incoming connections
		if err = startServer(ctx, server); err != nil {
			return err
		}

		return nil
	},
}

func configureServer(ctx context.Context, ip string, port int, connectionPool *pgxpool.Pool) (*http.Server, error) {
	userService, err := postgres.NewUserService(connectionPool)
	if err != nil {
		return nil, err
	}

	hasher := argon2.NewPasswordHasher(102400, 2, 8, 16, 32)

	router := gin.NewRouter(&gin.Controllers{
		AuthController: heimdall.NewAuthController(userService, hasher, log15.New(log15.Ctx{"module": "auth"})),
	})

	return &http.Server{
		Addr:    fmt.Sprintf("%s:%d", ip, port),
		Handler: router.Handler(),
	}, nil
}

func startServer(ctx context.Context, server *http.Server) error {
	group, ctx := errgroup.WithContext(ctx)

	// Start the HTTP server
	group.Go(func() error {
		log15.Info("Listening for connections", "address", server.Addr)
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
