package iam

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
)

// The weak-password rule used to live in the request contract, which meant the SDK ran it
// client-side and the server only got it because it validated through the same types.
// These pin it to the server, where a client cannot skip it by not calling Validate.

var errWeak = errors.New("password has been found in data breaches and is not secure")

type stubStrength struct {
	called   int
	rejectIt bool
}

func (s *stubStrength) Validate(_ context.Context, _ string) error {
	s.called++
	if s.rejectIt {
		return errWeak
	}
	return nil
}

func TestResetPassword_RejectsAWeakPasswordBeforeWritingIt(t *testing.T) {
	f := newPasswordServiceTestFixture()
	strength := &stubStrength{rejectIt: true}
	f.service.Strength = strength

	// Rigged so reaching the hasher would surface a different error. Getting errWeak back
	// therefore proves the rejection happened before the password went anywhere near
	// storage, not merely that it happened.
	f.hasher.hashError = errors.New("hasher should not have been reached")

	err := f.service.ResetPassword(context.Background(), "any-token", "hunter2hunter2")

	if !errors.Is(err, errWeak) {
		t.Fatalf("want the strength error surfaced, got %v", err)
	}
	if strength.called != 1 {
		t.Errorf("want the check run once, ran %d times", strength.called)
	}
}

func TestChangePassword_RejectsAWeakPassword(t *testing.T) {
	f := newPasswordServiceTestFixture()
	strength := &stubStrength{rejectIt: true}
	f.service.Strength = strength

	err := f.service.ChangePassword(context.Background(), uuid.New(), "old-password", "hunter2hunter2")

	if !errors.Is(err, errWeak) {
		t.Fatalf("want the strength error surfaced, got %v", err)
	}
	if strength.called != 1 {
		t.Errorf("want the check run once, ran %d times", strength.called)
	}
}

func TestVerifyEmailAndSetPassword_RejectsAWeakPassword(t *testing.T) {
	strength := &stubStrength{rejectIt: true}
	svc := &UserService{
		UserDB:              newMockUserDB(),
		Strength:            strength,
		Hasher:              &mockHasher{},
		VerificationTokenDB: newMockTokenDB(),
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	_, err := svc.VerifyEmailAndSetPassword(context.Background(), "any-token", "hunter2hunter2")

	if !errors.Is(err, errWeak) {
		t.Fatalf("want the strength error surfaced, got %v", err)
	}
	if strength.called != 1 {
		t.Errorf("want the check run once, ran %d times", strength.called)
	}
}

// A nil Strength leaves the check off, which is what the other unit tests rely on. It is
// worth pinning: the wiring in internal/app is the only thing that turns it on, so this
// says plainly that forgetting it means no check rather than a panic.
func TestStrengthIsSkippedWhenNotConfigured(t *testing.T) {
	f := newPasswordServiceTestFixture()
	f.service.Strength = nil

	// Fails for want of a token, not for want of a strength check.
	err := f.service.ResetPassword(context.Background(), "any-token", "hunter2hunter2")
	if errors.Is(err, errWeak) {
		t.Fatal("no strength configured, so no strength error should be possible")
	}
}
