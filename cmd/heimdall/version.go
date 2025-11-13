package main

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var (
	// Version is set at build time via ldflags (-X main.Version=x.y.z)
	Version = "dev"
)

var versionCmd = &cli.Command{
	Name:  "version",
	Usage: "Show version information",
	Action: func(c *cli.Context) error {
		fmt.Printf("heimdall version %s\n", Version)
		return nil
	},
}
