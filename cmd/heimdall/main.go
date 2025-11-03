package main

import (
	"log/slog"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "authsvc",
		Usage: "Authentication service for JWT token issuance",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "environment",
				Aliases: []string{"e"},
				Usage:   "Environment (development, staging, production)",
				Value:   "development",
				EnvVars: []string{"ENVIRONMENT"},
			},
		},
		Commands: []*cli.Command{
			startCmd,
			migrateCmd,
			versionCmd,
		},
	}

	if err := app.Run(os.Args); err != nil {
		slog.Error("Server shutdown", "error", err)
	}
}
