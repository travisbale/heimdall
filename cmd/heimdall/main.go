package main

import (
	"os"

	"github.com/inconshreveable/log15"
	"github.com/travisbale/heimdall/cmd/heimdall/start"
	cli "github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "heimdall",
		Usage: "RBAC service",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "debug",
				Aliases: []string{"d"},
				Usage:   "Enable debug output",
				EnvVars: []string{"HEIMDALL_DEBUG"},
			},
		},

		Commands: []*cli.Command{
			start.Command,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log15.Error("server shutdown", "err", err)
	}
}
