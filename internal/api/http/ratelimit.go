package http

import (
	"net/http"
	"time"

	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

// StrictRateLimit is for sensitive endpoints (10 req/min)
var StrictRateLimit = limiter.Rate{
	Period: 1 * time.Minute,
	Limit:  10,
}

// ModerateRateLimit is for standard auth endpoints (30 req/min)
var ModerateRateLimit = limiter.Rate{
	Period: 1 * time.Minute,
	Limit:  30,
}

// GenerousRateLimit is for less sensitive endpoints (100 req/min)
var GenerousRateLimit = limiter.Rate{
	Period: 1 * time.Minute,
	Limit:  100,
}

// newRateLimitMiddleware creates a rate limiting middleware with the specified rate
func newRateLimitMiddleware(rate limiter.Rate) func(http.Handler) http.Handler {
	// Use in-memory store for now (can be upgraded to Redis later)
	store := memory.NewStore()

	// Create limiter instance
	instance := limiter.New(store, rate)

	// Create stdlib middleware with IP-based key extraction
	middleware := stdlib.NewMiddleware(instance)

	// Return a function that wraps the handler
	return func(next http.Handler) http.Handler {
		return middleware.Handler(next)
	}
}
