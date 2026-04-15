package rest

import (
	"net/http"
	"time"

	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

var strictRateLimit = limiter.Rate{
	Period: 1 * time.Minute,
	Limit:  10,
}

var moderateRateLimit = limiter.Rate{
	Period: 1 * time.Minute,
	Limit:  30,
}

func rateLimitMiddleware(rate limiter.Rate, next http.HandlerFunc) http.HandlerFunc {
	store := memory.NewStore()
	instance := limiter.New(store, rate)
	middleware := stdlib.NewMiddleware(instance)

	return func(w http.ResponseWriter, r *http.Request) {
		middleware.Handler(http.HandlerFunc(next)).ServeHTTP(w, r)
	}
}

func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	origins := make(map[string]bool)
	for _, origin := range allowedOrigins {
		origins[origin] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origins[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", "300")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
