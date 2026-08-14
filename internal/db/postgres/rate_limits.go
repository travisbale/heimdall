package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/ulule/limiter/v3"
)

// RateLimitStore keeps limiter counters in the database so every instance shares them.
// The library's memory store is per-process, which multiplies the effective limit by
// however many containers are running.
type RateLimitStore struct {
	db *DB
}

func NewRateLimitStore(db *DB) *RateLimitStore {
	return &RateLimitStore{db: db}
}

// Get counts a request against the key's window and reports the result.
func (s *RateLimitStore) Get(ctx context.Context, key string, rate limiter.Rate) (limiter.Context, error) {
	row, err := s.db.Queries().IncrementRateLimit(ctx, sqlc.IncrementRateLimitParams{
		Key:    key,
		Window: interval(rate.Period),
	})
	if err != nil {
		return limiter.Context{}, fmt.Errorf("incrementing rate limit: %w", err)
	}
	return limitContext(rate, row.Count, row.ExpiresAt), nil
}

// Peek reports the current state without counting a request against it.
func (s *RateLimitStore) Peek(ctx context.Context, key string, rate limiter.Rate) (limiter.Context, error) {
	row, err := s.db.Queries().PeekRateLimit(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		// Nothing recorded is a full allowance, and the window starts when one is used.
		return limitContext(rate, 0, time.Now().Add(rate.Period)), nil
	}
	if err != nil {
		return limiter.Context{}, fmt.Errorf("reading rate limit: %w", err)
	}
	return limitContext(rate, row.Count, row.ExpiresAt), nil
}

// Reset clears the key's window.
func (s *RateLimitStore) Reset(ctx context.Context, key string, rate limiter.Rate) (limiter.Context, error) {
	if err := s.db.Queries().ResetRateLimit(ctx, key); err != nil {
		return limiter.Context{}, fmt.Errorf("resetting rate limit: %w", err)
	}
	return limitContext(rate, 0, time.Now().Add(rate.Period)), nil
}

// Increment is Get by another name for this store, which counts one request at a time.
// The interface allows a larger count; nothing here asks for one.
func (s *RateLimitStore) Increment(ctx context.Context, key string, count int64, rate limiter.Rate) (limiter.Context, error) {
	if count != 1 {
		return limiter.Context{}, fmt.Errorf("rate limit increment of %d is not supported", count)
	}
	return s.Get(ctx, key, rate)
}

// DeleteExpired removes windows that have lapsed. Expired rows are reused in place, so
// this only reclaims keys that stopped being asked about.
func (s *RateLimitStore) DeleteExpired(ctx context.Context) error {
	if err := s.db.Queries().DeleteExpiredRateLimits(ctx); err != nil {
		return fmt.Errorf("deleting expired rate limits: %w", err)
	}
	return nil
}

func limitContext(rate limiter.Rate, count int64, expiresAt time.Time) limiter.Context {
	remaining := rate.Limit - count
	if remaining < 0 {
		remaining = 0
	}
	return limiter.Context{
		Limit:     rate.Limit,
		Remaining: remaining,
		Reset:     expiresAt.Unix(),
		Reached:   count > rate.Limit,
	}
}

func interval(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
}
