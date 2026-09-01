package app

import (
	"encoding/hex"
	"fmt"

	"github.com/travisbale/knowhere/crypto/aes"
)

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
