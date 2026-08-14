package rest

import (
	"net/http"
	"time"

	"github.com/travisbale/knowhere/identity"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"strconv"
)

var strictRateLimit = limiter.Rate{
	Period: 1 * time.Minute,
	Limit:  10,
}

var moderateRateLimit = limiter.Rate{
	Period: 1 * time.Minute,
	Limit:  30,
}

func rateLimitMiddleware(store limiter.Store, rate limiter.Rate, next http.HandlerFunc) http.HandlerFunc {
	if store == nil {
		store = memory.NewStore()
	}
	instance := limiter.New(store, rate)

	return func(w http.ResponseWriter, r *http.Request) {
		// identity.ClientIP resolved this already, honouring TRUSTED_PROXY_MODE and taking
		// the X-Forwarded-For entry our own proxy appended rather than one a caller can
		// forge. The library's own key is RemoteAddr, which behind a proxy is the proxy —
		// putting every caller in one bucket.
		result, err := instance.Get(r.Context(), identity.GetIPAddress(r.Context()))
		if err != nil {
			http.Error(w, "rate limiter unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(result.Limit, 10))
		w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(result.Remaining, 10))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.Reset, 10))

		if result.Reached {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"Too many requests"}`))
			return
		}

		next(w, r)
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
