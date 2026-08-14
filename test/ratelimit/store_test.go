package ratelimit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/db/postgres"
	"github.com/ulule/limiter/v3"
)

const defaultDatabaseURL = "postgres://superuser:superuser@localhost:5432/heimdall?sslmode=disable"

// Each call is a separate pool, standing in for a separate instance.
func instance(t *testing.T) *postgres.RateLimitStore {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		url = defaultDatabaseURL
	}
	db, err := postgres.NewDB(context.Background(), url)
	if err != nil {
		t.Skipf("cannot reach the test database (%v). Run `make test-setup` first.", err)
	}
	t.Cleanup(db.Close)
	return postgres.NewRateLimitStore(db)
}

// The reason this store exists: two instances counting the same caller reach one total.
// A per-process store gives each of them a full allowance, so the effective limit is
// multiplied by however many containers are running.
func TestCountersAreSharedBetweenInstances(t *testing.T) {
	a, b := instance(t), instance(t)
	rate := limiter.Rate{Period: time.Minute, Limit: 4}
	key := "shared-" + uuid.NewString()
	ctx := context.Background()

	for i := range 3 {
		if _, err := a.Get(ctx, key, rate); err != nil {
			t.Fatalf("instance A request %d: %v", i+1, err)
		}
	}

	fourth, err := b.Get(ctx, key, rate)
	if err != nil {
		t.Fatalf("instance B: %v", err)
	}
	if fourth.Remaining != 0 {
		t.Errorf("instance B sees %d remaining of %d — counters are not shared", fourth.Remaining, rate.Limit)
	}
	if fourth.Reached {
		t.Error("the fourth request is within a limit of 4 and should be allowed")
	}

	fifth, err := b.Get(ctx, key, rate)
	if err != nil {
		t.Fatalf("instance B fifth: %v", err)
	}
	if !fifth.Reached {
		t.Error("the fifth request exceeds a limit of 4 and should be refused")
	}
}

// A lapsed window starts over rather than staying exhausted.
func TestWindowResetsOnceItLapses(t *testing.T) {
	s := instance(t)
	rate := limiter.Rate{Period: time.Second, Limit: 1}
	key := "lapsing-" + uuid.NewString()
	ctx := context.Background()

	if _, err := s.Get(ctx, key, rate); err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := s.Get(ctx, key, rate)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !second.Reached {
		t.Fatal("the second request exceeds a limit of 1 and should be refused")
	}

	time.Sleep(rate.Period + 300*time.Millisecond)

	after, err := s.Get(ctx, key, rate)
	if err != nil {
		t.Fatalf("after the window: %v", err)
	}
	if after.Reached {
		t.Error("the window lapsed, so the allowance should have started over")
	}
}

// Peek reports without spending, or checking a budget would consume it.
func TestPeekDoesNotCount(t *testing.T) {
	s := instance(t)
	rate := limiter.Rate{Period: time.Minute, Limit: 2}
	key := "peeking-" + uuid.NewString()
	ctx := context.Background()

	if _, err := s.Get(ctx, key, rate); err != nil {
		t.Fatalf("get: %v", err)
	}
	for i := range 3 {
		p, err := s.Peek(ctx, key, rate)
		if err != nil {
			t.Fatalf("peek %d: %v", i+1, err)
		}
		if p.Remaining != 1 {
			t.Fatalf("peek %d reports %d remaining, want 1 — peeking spent an allowance", i+1, p.Remaining)
		}
	}
}

// An unknown key is a whole allowance, not an error.
func TestPeekOnAnUnknownKey(t *testing.T) {
	s := instance(t)
	rate := limiter.Rate{Period: time.Minute, Limit: 5}
	p, err := s.Peek(context.Background(), "never-seen-"+uuid.NewString(), rate)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if p.Remaining != rate.Limit || p.Reached {
		t.Errorf("got %d remaining (reached=%v), want %d and not reached", p.Remaining, p.Reached, rate.Limit)
	}
}

func TestResetClearsTheWindow(t *testing.T) {
	s := instance(t)
	rate := limiter.Rate{Period: time.Minute, Limit: 1}
	key := "resetting-" + uuid.NewString()
	ctx := context.Background()

	if _, err := s.Get(ctx, key, rate); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := s.Reset(ctx, key, rate); err != nil {
		t.Fatalf("reset: %v", err)
	}
	after, err := s.Get(ctx, key, rate)
	if err != nil {
		t.Fatalf("after reset: %v", err)
	}
	if after.Reached {
		t.Error("the key was reset, so its allowance should be whole again")
	}
}
