package main

import (
	"log/slog"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "heimdall",
		Usage: "Multi-tenant authentication and authorization service",
		Flags: []cli.Flag{
			DebugFlag,
			LogFormatFlag,
			DatabaseURLFlag,
		},
		Before: func(c *cli.Context) error {
			var level slog.Level
			if config.Debug {
				level = slog.LevelDebug
			} else {
				level = slog.LevelInfo
			}

			opts := &slog.HandlerOptions{Level: level}

			// JSON format for production/log aggregation, text for local development
			var handler slog.Handler
			switch config.LogFormat {
			case "json":
				handler = slog.NewJSONHandler(os.Stderr, opts)
			case "text":
				handler = slog.NewTextHandler(os.Stderr, opts)
			default:
				slog.Error("Invalid log format. Defaulting to json", "format", config.LogFormat)
				handler = slog.NewJSONHandler(os.Stderr, opts)
			}

			slog.SetDefault(slog.New(handler))

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
