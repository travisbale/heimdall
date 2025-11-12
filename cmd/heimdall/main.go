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
			var level slog.Level
			if config.Debug {
				level = slog.LevelDebug
			} else {
				level = slog.LevelInfo
			}

			opts := &slog.HandlerOptions{Level: level}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, opts)))

			return nil
		},
		Commands: []*cli.Command{
			startCmd,
			migrateCmd,
			cleanupCmd,
			versionCmd,
		},
	}

	if err := app.Run(os.Args); err != nil {
		slog.Error("Application error", "error", err)
		os.Exit(1)
	}
}
