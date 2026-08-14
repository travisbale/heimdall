package sdk

import (
	"context"
	"strings"
	"testing"
)

// Length is the one password property the contract owns, so it is the one a client can
// reject without a round trip. Whether a password is guessable is the server's call.
func TestPasswordLengthIsValidatedByTheContract(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"a character short", strings.Repeat("a", MinPasswordLength-1), true},
		{"exactly the minimum", strings.Repeat("a", MinPasswordLength), false},
		{"exactly the maximum", strings.Repeat("a", MaxPasswordLength), false},
		{"a character over", strings.Repeat("a", MaxPasswordLength+1), true},
		{"empty", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := ResetPasswordRequest{Token: "t", NewPassword: tc.password}
			err := req.Validate(ctx)
			if tc.wantErr && err == nil {
				t.Errorf("want %q rejected, got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("want %q accepted, got %v", tc.name, err)
			}
		})
	}
}

// Counted in runes, not bytes: a Cyrillic or emoji password of the right length is the
// right length, and counting bytes would let a short one through as well as reject a
// legitimate one.
func TestPasswordLengthCountsRunesNotBytes(t *testing.T) {
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
			req := ResetPasswordRequest{Token: "t", NewPassword: tc.password}
			err := req.Validate(ctx)
			if tc.wantErr && err == nil {
				t.Errorf("want %q rejected, got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("want %q accepted, got %v", tc.name, err)
			}
		})
	}
}
