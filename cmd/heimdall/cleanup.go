package main

import (
	"context"
	"fmt"

	"github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/urfave/cli/v2"
)

var cleanupCmd = &cli.Command{
	Name:  "cleanup",
	Usage: "Clean up expired tokens, sessions, and old unverified users (run periodically via cron)",
	Flags: []cli.Flag{
		&cli.IntFlag{
			Name:  "unverified-user-age-days",
			Usage: "Delete unverified users older than this many days",
			Value: 7,
		},
	},
	Action: func(c *cli.Context) error {
		ctx := context.Background()

		db, err := postgres.NewDB(ctx, config.DatabaseURL)
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer db.Close()

		usersDB := postgres.NewUsersDB(db)
		oidcSessionsDB := postgres.NewOIDCSessionsDB(db)
		verificationTokensDB := postgres.NewVerificationTokensDB(db)
		passwordResetTokensDB := postgres.NewPasswordResetTokensDB(db)
		refreshTokensDB := postgres.NewRefreshTokensDB(db)

		fmt.Println("Deleting expired database records...")

		// Remove users who never verified email (reduces DB bloat from spam registrations)
		unverifiedUserAgeDays := int32(c.Int("unverified-user-age-days"))
		if err := usersDB.DeleteOldUnverifiedUsers(ctx, unverifiedUserAgeDays); err != nil {
			return fmt.Errorf("failed to delete old unverified users: %w", err)
		}
		fmt.Printf("Deleted old unverified users (age_days=%d)\n", unverifiedUserAgeDays)

		// Remove OAuth flow sessions that expired (typically 10-15 min expiry)
		if err := oidcSessionsDB.DeleteExpiredOIDCSessions(ctx); err != nil {
			return fmt.Errorf("failed to delete expired OIDC sessions: %w", err)
		}
		fmt.Println("Deleted expired OIDC sessions")

		// Remove expired email verification tokens (typically 24h expiry)
		if err := verificationTokensDB.DeleteExpiredTokens(ctx); err != nil {
			return fmt.Errorf("failed to delete expired verification tokens: %w", err)
		}
		fmt.Println("Deleted expired verification tokens")

		// Remove expired password reset tokens (typically 1h expiry)
		if err := passwordResetTokensDB.DeleteExpiredTokens(ctx); err != nil {
			return fmt.Errorf("failed to delete expired password reset tokens: %w", err)
		}
		fmt.Println("Deleted expired password reset tokens")

		// Remove expired and old revoked refresh tokens
		if err := refreshTokensDB.DeleteExpired(ctx); err != nil {
			return fmt.Errorf("failed to delete expired refresh tokens: %w", err)
		}
		fmt.Println("Deleted expired refresh tokens")

		fmt.Println("Database cleanup completed successfully")
		return nil
	},
}
