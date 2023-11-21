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
	"github.com/travisbale/heimdall/pkg/argon2"
	"github.com/travisbale/heimdall/pkg/jwt"
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
		&cli.StringFlag{
			Name:    "private-key",
			Usage:   "Private key file used to sign JWTs",
			Value:   "keys/heimdall.pem",
			EnvVars: []string{"PRIVATE_KEY_FILE"},
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

		// Create the database services
		userService, err := postgres.NewUserService(connectionPool)
		if err != nil {
			return err
		}
		permissionService, err := postgres.NewPermissionService(connectionPool)
		if err != nil {
			return err
		}

		// Create the JWT Service used to sign and verify tokens
		privateKey, err := os.ReadFile(c.String("private-key"))
		if err != nil {
			return err
		}
		jwtService, err := jwt.NewJWTService("heimdall", privateKey)
		if err != nil {
			return err
		}

		// Create the controllers
		authController := heimdall.NewAuthController(&heimdall.AuthControllerConfig{
			UserService:       userService,
			PermissionService: permissionService,
			Hasher:            argon2.NewPasswordHasher(102400, 2, 8, 16, 32),
			Logger:            log15.New(log15.Ctx{"module": "auth"}),
		})

		// Create the request router
		router := gin.NewRouter(&gin.Config{
			TokenService:   jwtService,
			AuthController: authController,
		})

		// Create the HTTP server
		server := &http.Server{
			Addr:    fmt.Sprintf("%s:%d", c.String("ip"), c.Int("port")),
			Handler: router.Handler(),
		}

		// Start listening for incoming connections
		if err = startServer(ctx, server); err != nil {
			return err
		}

		return nil
	},
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
