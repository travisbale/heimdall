package password

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestValidator_Validate_Length(t *testing.T) {
	validator := NewValidator()
	ctx := context.Background()

	for _, tc := range []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"a character short", "Xk7mQp2wR"[:MinLength-1], true},
		{"exactly the minimum", "Xk7mQp2wRt", false},
		{"exactly the maximum", "Xk7mQp2wRt" + strings.Repeat("z", MaxLength-10), false},
		{"a character over", "Xk7mQp2wRt" + strings.Repeat("z", MaxLength-9), true},
		{"empty", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No breach lookup: a length verdict must not depend on the network.
			validator.httpClient = &http.Client{Transport: &mockTransport{statusCode: http.StatusNotFound}}
			err := validator.Validate(ctx, tc.password)
			if tc.wantErr && err == nil {
				t.Errorf("want %q rejected, got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("want %q accepted, got %v", tc.name, err)
			}
		})
	}
}

// Counted in runes, not bytes: counting bytes would reject a legitimate Cyrillic password
// and accept a shorter one.
func TestValidator_Validate_CountsRunesNotBytes(t *testing.T) {
	validator := NewValidator()
	ctx := context.Background()

	for _, tc := range []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"ten Cyrillic characters", "пароль1234", false},
		{"ten runes including emoji", "MyPass😀🔐12", false},
		{"six Cyrillic characters is short despite twelve bytes", "пароль", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			validator.httpClient = &http.Client{Transport: &mockTransport{statusCode: http.StatusNotFound}}
			err := validator.Validate(ctx, tc.password)
			if tc.wantErr && err == nil {
				t.Errorf("want %q rejected, got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("want %q accepted, got %v", tc.name, err)
			}
		})
	}
}

func TestValidator_Validate_CommonPasswords(t *testing.T) {
	validator := NewValidator()
	ctx := context.Background()

	tests := []struct {
		name        string
		password    string
		shouldError bool
	}{
		{
			name:        "common password 'password123'",
			password:    "password123",
			shouldError: true,
		},
		{
			name:        "common password '1234567890'",
			password:    "1234567890",
			shouldError: true,
		},
		{
			name:        "common password case insensitive",
			password:    "PASSWORD123",
			shouldError: true,
		},
		{
			name:        "common keyboard pattern",
			password:    "qwertyuiop",
			shouldError: true,
		},
		{
			name:        "uncommon password",
			password:    "MyV3ryStr0ngP@ssw0rd!",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock HTTP client to avoid actual API calls
			validator.httpClient = &http.Client{
				Transport: &mockTransport{statusCode: http.StatusNotFound},
			}

			err := validator.Validate(ctx, tt.password)
			if tt.shouldError && err == nil {
				t.Errorf("expected error for common password but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
			if tt.shouldError && err != nil {
				if !strings.Contains(err.Error(), "too common") {
					t.Errorf("expected 'too common' error, got: %v", err)
				}
			}
		})
	}
}

func TestValidator_Validate_Breached(t *testing.T) {
	ctx := context.Background()

	// A round tripper rather than a test server: HIBPURL is a const, so only intercepting the
	// transport reaches the request. A server the validator never calls proves nothing.
	answering := func(t *testing.T, body string) *Validator {
		t.Helper()
		v := NewValidator()
		v.httpClient = &http.Client{Transport: &mockTransport{statusCode: http.StatusOK, response: body}}
		return v
	}

	t.Run("a suffix the corpus returns is refused", func(t *testing.T) {
		password := "MySecurePass"

		if err := answering(t, hibpSuffix(password)+":12345\n").Validate(ctx, password); !errors.Is(err, ErrBreached) {
			t.Fatalf("want ErrBreached, got %v", err)
		}
	})

	// The prefix is all that leaves; the suffix is matched here, so a corpus answering with
	// other hashes under the same prefix must not tar this password with them.
	t.Run("other suffixes under the same prefix are accepted", func(t *testing.T) {
		password := "MySecurePass"
		body := "0000000000000000000000000000000000001:9\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3\n"

		if err := answering(t, body).Validate(ctx, password); err != nil {
			t.Fatalf("want the password accepted, got %v", err)
		}
	})

	t.Run("a count of zero is not a breach", func(t *testing.T) {
		password := "MySecurePass"

		if err := answering(t, hibpSuffix(password)+":0\n").Validate(ctx, password); err != nil {
			t.Fatalf("want a zero count accepted, got %v", err)
		}
	})

	t.Run("API unreachable", func(t *testing.T) {
		validator := NewValidator()
		validator.httpClient = &http.Client{
			Transport: &mockTransport{statusCode: http.StatusInternalServerError},
		}

		// Should not fail validation if API is down
		err := validator.Validate(ctx, "ThisIsAGoodPassword123")
		if err != nil {
			t.Errorf("expected no error when API is unreachable, got: %v", err)
		}
	})
}

func TestValidator_isCommonPassword(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		password string
		isCommon bool
	}{
		{"password123", true},
		{"1234567890", true},
		{"qwertyuiop", true},
		{"PASSWORD123", true}, // case insensitive
		{"QwErTyUiOp", true},  // mixed case
		{"ThisIsNotCommon123", false},
		{"random_secure_p@ss", false},
	}

	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			result := validator.isCommonPassword(tt.password)
			if result != tt.isCommon {
				t.Errorf("isCommonPassword(%q) = %v, want %v", tt.password, result, tt.isCommon)
			}
		})
	}
}

// hibpSuffix is the part of a password's SHA-1 the corpus answers with — everything after the
// five characters k-anonymity allows off the machine.
func hibpSuffix(password string) string {
	sum := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(sum[:]))[5:]
}

type mockTransport struct {
	statusCode int
	response   string
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(strings.NewReader(m.response)),
		Header:     make(http.Header),
	}, nil
}
