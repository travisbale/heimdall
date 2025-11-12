package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/urfave/cli/v2"
)

var cleanupCmd = &cli.Command{
	Name:  "cleanup",
	Usage: "Clean up expired database records",
	Flags: []cli.Flag{
		&cli.IntFlag{
			Name:  "unverified-user-age-days",
			Usage: "Delete unverified users older than this many days",
			Value: 7,
		},
	},
	Action: func(c *cli.Context) error {
		ctx := context.Background()

		// Connect to database
		db, err := postgres.NewDB(ctx, config.DatabaseURL, slog.Default())
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer db.Close()

		// Create repositories
		usersDB := postgres.NewUsersDB(db)
		oidcSessionsDB := postgres.NewOIDCSessionsDB(db)
		verificationTokensDB := postgres.NewVerificationTokensDB(db)
		passwordResetTokensDB := postgres.NewPasswordResetTokensDB(db)

		slog.Info("Deleting expired database records...")

		// Delete old unverified users
		unverifiedUserAgeDays := int32(c.Int("unverified-user-age-days"))
		if err := usersDB.DeleteOldUnverifiedUsers(ctx, unverifiedUserAgeDays); err != nil {
			return fmt.Errorf("failed to delete old unverified users: %w", err)
		}
		slog.Info("Deleted old unverified users", "age_days", unverifiedUserAgeDays)

		// Delete expired OIDC sessions
		if err := oidcSessionsDB.DeleteExpiredOIDCSessions(ctx); err != nil {
			return fmt.Errorf("failed to delete expired OIDC sessions: %w", err)
		}
		slog.Info("Deleted expired OIDC sessions")

		// Delete expired verification tokens
		if err := verificationTokensDB.DeleteExpiredTokens(ctx); err != nil {
			return fmt.Errorf("failed to delete expired verification tokens: %w", err)
		}
		slog.Info("Deleted expired verification tokens")

		// Delete expired password reset tokens
		if err := passwordResetTokensDB.DeleteExpiredTokens(ctx); err != nil {
			return fmt.Errorf("failed to delete expired password reset tokens: %w", err)
		}
		slog.Info("Deleted expired password reset tokens")

		slog.Info("Database cleanup completed successfully")
		return nil
	},
}
