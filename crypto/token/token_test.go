package token

import (
	"encoding/base64"
	"testing"
)

func TestGenerate_Success(t *testing.T) {
	testCases := []struct {
		numBytes  int
		minLength int // Base64 encoded length
		maxLength int
	}{
		{16, 21, 23}, // 16 bytes -> ~21-23 chars
		{32, 42, 44}, // 32 bytes -> ~42-44 chars
		{64, 85, 87}, // 64 bytes -> ~85-87 chars
	}

	for _, tc := range testCases {
		token, err := Generate(tc.numBytes)
		if err != nil {
			t.Errorf("numBytes=%d: expected no error, got %v", tc.numBytes, err)
			continue
		}

		if token == "" {
			t.Errorf("numBytes=%d: expected non-empty token", tc.numBytes)
			continue
		}

		// Check length is in expected range
		if len(token) < tc.minLength || len(token) > tc.maxLength {
			t.Errorf("numBytes=%d: expected length between %d and %d, got %d",
				tc.numBytes, tc.minLength, tc.maxLength, len(token))
		}

		// Verify it's valid base64 URL-safe encoding
		_, err = base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(token)
		if err != nil {
			t.Errorf("numBytes=%d: token is not valid base64 URL-safe: %v", tc.numBytes, err)
		}
	}
}

func TestGenerate_Randomness(t *testing.T) {
	// Generate multiple tokens and verify they're all different
	const numTokens = 100
	const tokenSize = 32

	tokens := make(map[string]bool)

	for range numTokens {
		token, err := Generate(tokenSize)
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		if tokens[token] {
			t.Errorf("generated duplicate token: %s", token)
		}
		tokens[token] = true
	}

	if len(tokens) != numTokens {
		t.Errorf("expected %d unique tokens, got %d", numTokens, len(tokens))
	}
}

func TestGenerate_ZeroBytes(t *testing.T) {
	token, err := Generate(0)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if token != "" {
		t.Errorf("expected empty token for 0 bytes, got %s", token)
	}
}

func TestGenerate_SmallSize(t *testing.T) {
	token, err := Generate(1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if token == "" {
		t.Error("expected non-empty token")
	}

	// Should be valid base64
	_, err = base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(token)
	if err != nil {
		t.Errorf("token is not valid base64: %v", err)
	}
}

func TestGenerate_LargeSize(t *testing.T) {
	token, err := Generate(256)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(token) == 0 {
		t.Error("expected non-empty token")
	}

	// Verify can decode back to 256 bytes
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(token)
	if err != nil {
		t.Fatalf("failed to decode token: %v", err)
	}

	if len(decoded) != 256 {
		t.Errorf("expected 256 decoded bytes, got %d", len(decoded))
	}
}

func TestGenerate_NoPadding(t *testing.T) {
	token, err := Generate(32)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify token has no padding characters
	if len(token) > 0 && token[len(token)-1] == '=' {
		t.Error("expected no padding in token")
	}
}

func TestGenerate_URLSafeCharacters(t *testing.T) {
	token, err := Generate(32)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// URL-safe base64 uses - and _ instead of + and /
	for _, char := range token {
		if char == '+' || char == '/' {
			t.Errorf("token contains non-URL-safe character: %c", char)
		}
	}
}
