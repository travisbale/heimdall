package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/travisbale/knowhere/identity"
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
			initLogger(config.LogFormat, config.Debug)
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
		fmt.Fprintf(os.Stderr, "Application error: %v\n", err)
		os.Exit(1)
	}
}

func initLogger(format string, debug bool) {
	var level slog.Level
	if debug {
		level = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	slog.SetDefault(slog.New(identity.LogHandler(handler)))
}
