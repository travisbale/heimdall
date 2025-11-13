package main

import (
	"fmt"

	"github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/urfave/cli/v2"
)

var migrateCmd = &cli.Command{
	Name:  "migrate",
	Usage: "Manage database schema migrations",
	Subcommands: []*cli.Command{
		{
			Name:  "up",
			Usage: "Apply all pending migrations",
			Action: func(c *cli.Context) error {
				return postgres.MigrateUp(config.DatabaseURL)
			},
		},
		{
			Name:  "down",
			Usage: "Rollback most recent migration (use with caution)",
			Action: func(c *cli.Context) error {
				return postgres.MigrateDown(config.DatabaseURL)
			},
		},
		{
			Name:  "version",
			Usage: "Show current migration version (dirty = failed migration)",
			Action: func(c *cli.Context) error {
				version, dirty, err := postgres.MigrateVersion(config.DatabaseURL)
				if err != nil {
					return err
				}
				if dirty {
					fmt.Printf("Current version: %d (dirty)\n", version)
				} else {
					fmt.Printf("Current version: %d\n", version)
				}
				return nil
			},
		},
	},
}
