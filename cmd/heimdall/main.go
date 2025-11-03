package main

import (
	"log/slog"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "heimdall",
		Usage: "Authentication service for JWT token issuance",
		Flags: []cli.Flag{
			DebugFlag,
			DatabaseURLFlag,
		},
		Before: func(c *cli.Context) error {
			// Set log level based on debug flag
			if c.Bool("debug") {
				slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
					Level: slog.LevelDebug,
				})))
			} else {
				slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
					Level: slog.LevelInfo,
				})))
			}
			return nil
		},
		Commands: []*cli.Command{
			startCmd,
			migrateCmd,
			versionCmd,
		},
	}

	if err := app.Run(os.Args); err != nil {
		slog.Error("Application error", "error", err)
		os.Exit(1)
	}
}
