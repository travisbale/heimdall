package main

import (
	"fmt"
	"os"

	"github.com/travisbale/heimdall/clog"
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
			// Default to json if invalid format provided
			format := config.LogFormat

			if format != "json" && format != "text" {
				fmt.Fprintf(os.Stderr, "Invalid log format %q. Defaulting to json\n", format)
				format = "json"
			}

			return clog.Init(format, config.Debug)
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
