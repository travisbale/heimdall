package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/travisbale/knowhere/identity"
	"github.com/ulule/limiter/v3"
)

// The limiter used to key on RemoteAddr, which behind a proxy is the proxy — so one
// caller exhausting the bucket locked out everyone. In production that made a 10/min
// login limit a global one.
func TestRateLimitIsPerClientNotGlobal(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	handler := identity.ClientIP(true)(rateLimitMiddleware(limiter.Rate{Period: time.Minute, Limit: 2}, ok))

	send := func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", ip)
		req.RemoteAddr = "10.0.0.1:1234" // the proxy: identical for every caller
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	for i := range 2 {
		if got := send("203.0.113.10"); got != http.StatusOK {
			t.Fatalf("request %d from the first client: got %d, want 200", i+1, got)
		}
	}
	if got := send("203.0.113.10"); got != http.StatusTooManyRequests {
		t.Errorf("first client over its limit: got %d, want 429", got)
	}

	// A different client, same proxy. It must have its own allowance.
	if got := send("198.51.100.20"); got != http.StatusOK {
		t.Errorf("second client: got %d, want 200 — buckets are shared", got)
	}
}

// Without a trusted proxy the header is a caller's to set, so it must not buy a fresh
// allowance by changing it.
func TestRateLimitIgnoresForwardedHeaderWhenProxyIsNotTrusted(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	handler := identity.ClientIP(false)(rateLimitMiddleware(limiter.Rate{Period: time.Minute, Limit: 1}, ok))

	send := func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Forwarded-For", ip)
		req.RemoteAddr = "203.0.113.99:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	if got := send("203.0.113.10"); got != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", got)
	}
	if got := send("198.51.100.20"); got != http.StatusTooManyRequests {
		t.Errorf("a forged header bought a fresh allowance: got %d, want 429", got)
	}
}
