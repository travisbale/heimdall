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
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "database-url",
					Aliases: []string{"u"},
					Usage:   "PostgreSQL connection URL",
					Value:   "postgres://authsvc:authsvc_dev_password@localhost:5432/authsvc?sslmode=disable",
					EnvVars: []string{"DATABASE_URL"},
				},
			},
			Action: func(c *cli.Context) error {
				databaseURL := c.String("database-url")
				return postgres.MigrateUp(databaseURL)
			},
		},
		{
			Name:  "down",
			Usage: "Rollback the last migration",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "database-url",
					Aliases: []string{"u"},
					Usage:   "PostgreSQL connection URL",
					Value:   "postgres://authsvc:authsvc_dev_password@localhost:5432/authsvc?sslmode=disable",
					EnvVars: []string{"DATABASE_URL"},
				},
			},
			Action: func(c *cli.Context) error {
				databaseURL := c.String("database-url")
				return postgres.MigrateDown(databaseURL)
			},
		},
		{
			Name:  "version",
			Usage: "Show current migration version",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "database-url",
					Aliases: []string{"u"},
					Usage:   "PostgreSQL connection URL",
					Value:   "postgres://authsvc:authsvc_dev_password@localhost:5432/authsvc?sslmode=disable",
					EnvVars: []string{"DATABASE_URL"},
				},
			},
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
