package rest

import (
	"net/http"
	"time"

	"github.com/travisbale/knowhere/identity"
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
	instance := limiter.New(memory.NewStore(), rate)

	// The library keys on RemoteAddr, which behind a proxy is the proxy — one bucket for
	// everyone. identity.ClientIP has already resolved the caller, honouring
	// TRUSTED_PROXY_MODE and taking the X-Forwarded-For entry our proxy appended rather
	// than the leftmost one a caller can forge.
	middleware := stdlib.NewMiddleware(instance, stdlib.WithKeyGetter(func(r *http.Request) string {
		return identity.GetIPAddress(r.Context())
	}))

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
