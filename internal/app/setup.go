package app

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/travisbale/knowhere/crypto/aes"
)

// setupDatabase connects to PostgreSQL and runs migrations
func setupDatabase(ctx context.Context, databaseURL string) (*postgres.DB, error) {
	db, err := postgres.NewDB(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run migrations on startup to ensure schema is current
	if err := postgres.MigrateUp(databaseURL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run database migrations: %w", err)
	}

	return db, nil
}

// setupEncryption creates AES cipher for encrypting OIDC client secrets
func setupEncryption(encryptionKey string) (*aes.Cipher, error) {
	// AES cipher encrypts client secrets for OIDC providers stored in database
	encryptionKeyBytes, err := hex.DecodeString(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key (must be 64 hex characters): %w", err)
	}

	cipher, err := aes.NewCipher(encryptionKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption cipher: %w", err)
	}

	return cipher, nil
}
