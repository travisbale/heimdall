package aes

import (
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple text", "hello world"},
		{"empty string", ""},
		{"unicode", "Hello 世界 🌍"},
		{"long text", strings.Repeat("a", 10000)},
		{"special chars", "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{"multiline", "line1\nline2\nline3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := cipher.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Verify ciphertext is base64-encoded
			if ciphertext == "" && tt.plaintext != "" {
				t.Error("Encrypt() returned empty ciphertext for non-empty plaintext")
			}

			// Decrypt
			decrypted, err := cipher.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// Verify decrypted matches original
			if decrypted != tt.plaintext {
				t.Errorf("Decrypt() = %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptDifferentCiphertexts(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}

	plaintext := "same plaintext"

	// Encrypt the same plaintext twice
	ciphertext1, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	ciphertext2, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Ciphertexts should be different (different nonces)
	if ciphertext1 == ciphertext2 {
		t.Error("Encrypt() produced same ciphertext twice (nonce reuse)")
	}

	// But both should decrypt to the same plaintext
	decrypted1, _ := cipher.Decrypt(ciphertext1)
	decrypted2, _ := cipher.Decrypt(ciphertext2)

	if decrypted1 != plaintext || decrypted2 != plaintext {
		t.Error("Decrypt() failed to decrypt different ciphertexts")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	cipher1, _ := NewCipher(key1)
	cipher2, _ := NewCipher(key2)

	plaintext := "secret message"
	ciphertext, err := cipher1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Try to decrypt with wrong key
	_, err = cipher2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt() should fail with wrong key")
	}

	if !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("Decrypt() error = %v, want 'decryption failed'", err)
	}
}

func TestInvalidKeyLength(t *testing.T) {
	tests := []struct {
		name      string
		keyLength int
	}{
		{"16 bytes", 16},
		{"24 bytes", 24},
		{"31 bytes", 31},
		{"33 bytes", 33},
		{"0 bytes", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLength)

			_, err := NewCipher(key)
			if err == nil {
				t.Error("NewCipher() should fail with invalid key length")
			}

			if !strings.Contains(err.Error(), "key must be exactly 32 bytes") {
				t.Errorf("NewCipher() error = %v, want 'key must be exactly 32 bytes'", err)
			}
		})
	}
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	cipher, _ := NewCipher(key)

	tests := []struct {
		name       string
		ciphertext string
		wantErr    string
	}{
		{"invalid base64", "not-valid-base64!", "failed to decode base64"},
		{"too short", "YWJj", "ciphertext too short"},
		{"corrupted data", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=", "decryption failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cipher.Decrypt(tt.ciphertext)
			if err == nil {
				t.Error("Decrypt() should fail with invalid ciphertext")
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Decrypt() error = %v, want to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("GenerateKey() returned %d bytes, want 32", len(key1))
	}

	// Generate another key and verify they're different
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if string(key1) == string(key2) {
		t.Error("GenerateKey() produced same key twice")
	}
}

func TestGenerateKeyIsRandom(t *testing.T) {
	// Generate multiple keys and verify they're all different
	keys := make(map[string]bool)
	for range 100 {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}

		keyStr := string(key)
		if keys[keyStr] {
			t.Error("GenerateKey() produced duplicate key")
		}
		keys[keyStr] = true
	}
}
