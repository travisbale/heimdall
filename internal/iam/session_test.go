package iam

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/knowhere/identity"
)

const clientAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"

// The grace path only runs for a request that looks like the client the token was issued to.
func sameClient(ctx context.Context) context.Context {
	return identity.WithUserAgent(ctx, clientAgent)
}

// mockRefreshTokenDB records what RotateSession did rather than what it was asked, since the
// difference between a retry and a theft is which of revoke-one and revoke-family ran.
type mockRefreshTokenDB struct {
	stored          *RefreshToken
	getErr          error
	liveInFamily    int64
	countErr        error
	revokedHashes   []string
	revokedFamilies []uuid.UUID
}

func (m *mockRefreshTokenDB) Create(ctx context.Context, t *RefreshToken) (*RefreshToken, error) {
	return t, nil
}

func (m *mockRefreshTokenDB) GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	return m.stored, m.getErr
}

func (m *mockRefreshTokenDB) GetByHashIncludingRevoked(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	return m.stored, m.getErr
}

func (m *mockRefreshTokenDB) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*RefreshToken, error) {
	return nil, nil
}

func (m *mockRefreshTokenDB) UpdateLastUsed(ctx context.Context, id uuid.UUID) error { return nil }

func (m *mockRefreshTokenDB) RevokeByID(ctx context.Context, id uuid.UUID) error { return nil }

func (m *mockRefreshTokenDB) RevokeByHash(ctx context.Context, tokenHash string) error {
	m.revokedHashes = append(m.revokedHashes, tokenHash)
	return nil
}

func (m *mockRefreshTokenDB) RevokeByFamilyID(ctx context.Context, familyID uuid.UUID) error {
	m.revokedFamilies = append(m.revokedFamilies, familyID)
	return nil
}

func (m *mockRefreshTokenDB) CountLiveInFamily(ctx context.Context, familyID uuid.UUID) (int64, error) {
	return m.liveInFamily, m.countErr
}

func (m *mockRefreshTokenDB) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	return nil
}

func (m *mockRefreshTokenDB) DeleteExpired(ctx context.Context) error { return nil }

func newSessionService(db *mockRefreshTokenDB) *SessionService {
	return &SessionService{RefreshTokenDB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func spentToken(ago time.Duration) *RefreshToken {
	revoked := time.Now().Add(-ago)
	return &RefreshToken{ID: uuid.New(), UserID: uuid.New(), FamilyID: uuid.New(), RevokedAt: &revoked, UserAgent: clientAgent}
}

func TestRotationSpendsTheTokenItWasGiven(t *testing.T) {
	db := &mockRefreshTokenDB{stored: &RefreshToken{ID: uuid.New(), FamilyID: uuid.New()}}
	svc := newSessionService(db)

	if _, err := svc.RotateSession(sameClient(context.Background()), "raw-token"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if len(db.revokedHashes) != 1 {
		t.Errorf("want the presented token revoked once, got %d", len(db.revokedHashes))
	}
	if len(db.revokedFamilies) != 0 {
		t.Errorf("want the family left alone, got %v", db.revokedFamilies)
	}
}

// The case the grace window exists for: the rotation landed, its response did not, and the
// client came back with the only value it has.
func TestARetriedRotationIsNotTreatedAsTheft(t *testing.T) {
	db := &mockRefreshTokenDB{stored: spentToken(2 * time.Second), liveInFamily: 1}
	svc := newSessionService(db)

	got, err := svc.RotateSession(sameClient(context.Background()), "raw-token")
	if err != nil {
		t.Fatalf("want the retry allowed, got %v", err)
	}
	if got == nil {
		t.Fatal("want the session back, got nil")
	}
	if len(db.revokedFamilies) != 0 {
		t.Errorf("want the family intact, got %v", db.revokedFamilies)
	}
}

func TestAReplayAfterTheGraceWindowRevokesTheFamily(t *testing.T) {
	db := &mockRefreshTokenDB{stored: spentToken(rotationGrace + time.Second), liveInFamily: 1}
	svc := newSessionService(db)

	if _, err := svc.RotateSession(sameClient(context.Background()), "raw-token"); !errors.Is(err, ErrTokenReused) {
		t.Fatalf("want ErrTokenReused, got %v", err)
	}
	if len(db.revokedFamilies) != 1 {
		t.Errorf("want the family revoked once, got %d", len(db.revokedFamilies))
	}
}

// Without the liveness check a grace period would undo the answer to a real theft: every token
// in a revoked family carries a fresh RevokedAt, so a stolen one would arrive inside the window.
func TestAReplayIntoAnAlreadyRevokedFamilyIsStillTheft(t *testing.T) {
	db := &mockRefreshTokenDB{stored: spentToken(2 * time.Second), liveInFamily: 0}
	svc := newSessionService(db)

	if _, err := svc.RotateSession(sameClient(context.Background()), "raw-token"); !errors.Is(err, ErrTokenReused) {
		t.Fatalf("want ErrTokenReused, got %v", err)
	}
	if len(db.revokedFamilies) != 1 {
		t.Errorf("want the family revoked once, got %d", len(db.revokedFamilies))
	}
}

func TestAFailedLivenessCheckIsTreatedAsTheft(t *testing.T) {
	db := &mockRefreshTokenDB{stored: spentToken(2 * time.Second), countErr: errors.New("database down")}
	svc := newSessionService(db)

	if _, err := svc.RotateSession(sameClient(context.Background()), "raw-token"); !errors.Is(err, ErrTokenReused) {
		t.Fatalf("want the unknown answer to fail closed, got %v", err)
	}
}

// A stolen cookie replayed from somewhere else is the case the window must not cover.
func TestAReplayFromAnotherClientIsStillTheft(t *testing.T) {
	db := &mockRefreshTokenDB{stored: spentToken(2 * time.Second), liveInFamily: 1}
	svc := newSessionService(db)

	ctx := identity.WithUserAgent(context.Background(), "curl/8.4.0")
	if _, err := svc.RotateSession(ctx, "raw-token"); !errors.Is(err, ErrTokenReused) {
		t.Fatalf("want ErrTokenReused, got %v", err)
	}
	if len(db.revokedFamilies) != 1 {
		t.Errorf("want the family revoked once, got %d", len(db.revokedFamilies))
	}
}

// Fail closed rather than letting two blanks match: a request with no user agent has not shown
// it is the client the token was issued to.
func TestAReplayWithNoUserAgentIsStillTheft(t *testing.T) {
	spent := spentToken(2 * time.Second)
	spent.UserAgent = ""
	db := &mockRefreshTokenDB{stored: spent, liveInFamily: 1}
	svc := newSessionService(db)

	if _, err := svc.RotateSession(context.Background(), "raw-token"); !errors.Is(err, ErrTokenReused) {
		t.Fatalf("want ErrTokenReused, got %v", err)
	}
}
