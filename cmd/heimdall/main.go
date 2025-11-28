package main

import (
	"fmt"
	"os"

	"github.com/travisbale/uatu/ulog"
	"github.com/urfave/cli/v2"
)

// logHandler holds the ulog handler for cleanup on shutdown
var logHandler *ulog.Handler

func main() {
	app := &cli.App{
		Name:  "heimdall",
		Usage: "Multi-tenant authentication and authorization service",
		Flags: []cli.Flag{
			DebugFlag,
			LogFormatFlag,
			DatabaseURLFlag,
			UatuGRPCAddressFlag,
		},
		Before: func(c *cli.Context) error {
			var err error
			logHandler, err = ulog.Init(&ulog.InitConfig{
				Service: "heimdall",
				Address: config.UatuGRPCAddress,
				Format:  config.LogFormat,
				Debug:   config.Debug,
			})
			return err
		},
		After: func(c *cli.Context) error {
			if logHandler != nil {
				return logHandler.Close()
			}
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
