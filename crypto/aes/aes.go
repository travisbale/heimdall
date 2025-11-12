package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Cipher provides AES-256-GCM encryption and decryption
type Cipher struct {
	gcm cipher.AEAD
}

// NewCipher creates a new AES-256-GCM cipher with the provided key
//
// Parameters:
//   - key: A 32-byte (256-bit) encryption key
//
// Returns an initialized Cipher ready for encryption/decryption
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes (256 bits), got %d bytes", len(key))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &Cipher{gcm: gcm}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM and returns a base64-encoded string.
// The nonce is prepended to the ciphertext for storage.
//
// Format: [nonce(12 bytes)][ciphertext][auth tag(16 bytes)]
//
// Parameters:
//   - plaintext: The string to encrypt
//
// Returns a base64-encoded string containing nonce + ciphertext + tag
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	// Generate a random nonce (12 bytes is recommended for GCM)
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	// GCM appends the authentication tag to the ciphertext
	ciphertext := c.gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Encode to base64 for storage
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext using AES-256-GCM.
//
// Parameters:
//   - ciphertext: Base64-encoded string containing nonce + ciphertext + tag
//
// Returns the decrypted plaintext string
func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	// Decode from base64
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Validate minimum length (nonce + tag)
	nonceSize := c.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]

	// Decrypt and verify authentication tag
	plaintext, err := c.gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed (invalid key or corrupted data): %w", err)
	}

	return string(plaintext), nil
}

// GenerateKey generates a cryptographically secure 32-byte (256-bit) AES key
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}
