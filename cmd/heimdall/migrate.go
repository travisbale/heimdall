package main

import (
	"fmt"

	"github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/urfave/cli/v2"
)

var migrateCmd = &cli.Command{
	Name:  "migrate",
	Usage: "Run database migrations",
	Subcommands: []*cli.Command{
		{
			Name:  "up",
			Usage: "Apply all pending migrations",
			Action: func(c *cli.Context) error {
				databaseURL := c.String("database-url")
				return postgres.MigrateUp(databaseURL)
			},
		},
		{
			Name:  "down",
			Usage: "Rollback the last migration",
			Action: func(c *cli.Context) error {
				databaseURL := c.String("database-url")
				return postgres.MigrateDown(databaseURL)
			},
		},
		{
			Name:  "version",
			Usage: "Show current migration version",
			Action: func(c *cli.Context) error {
				databaseURL := c.String("database-url")
				version, dirty, err := postgres.MigrateVersion(databaseURL)
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
