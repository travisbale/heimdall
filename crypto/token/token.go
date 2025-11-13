package token

import (
	"crypto/rand"
	"encoding/base64"
)

// Generate creates a cryptographically secure random token of the specified byte length
// Returns base64 URL-safe encoded string without padding
func Generate(numBytes int) (string, error) {
	bytes := make([]byte, numBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes), nil
}
