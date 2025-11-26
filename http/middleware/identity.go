package middleware

import (
	"net/http"
	"strings"

	"github.com/travisbale/heimdall/identity"
)

// ClientIP extracts the client IP address and adds it to the request context
// This should run before logging middleware so IP is available for log enrichment
func ClientIP(trustedProxyMode bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIPAddress(r, trustedProxyMode)
			ctx := identity.WithIPAddress(r.Context(), ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractIPAddress extracts the client IP address from the request with security validation
func extractIPAddress(r *http.Request, trustedProxyMode bool) string {
	// Behind trusted reverse proxy - extract from proxy headers
	if trustedProxyMode {
		var ip string

		// Take the rightmost IP (last entry added by our trusted proxy)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				ip = strings.TrimSpace(ips[len(ips)-1])
			}
		}

		// Fallback to X-Real-IP if X-Forwarded-For not present
		if ip == "" {
			if xri := r.Header.Get("X-Real-IP"); xri != "" {
				ip = strings.TrimSpace(xri)
			}
		}

		// Last resort: use RemoteAddr
		if ip != "" {
			return ip
		}
	}

	// Direct connection or untrusted proxy - use RemoteAddr
	// RemoteAddr format is "IP:port", extract just the IP
	if host, _, ok := strings.Cut(r.RemoteAddr, ":"); ok {
		return host
	}

	return r.RemoteAddr
}

// UserAgent extracts the User-Agent header and adds it to the request context
// Used for session tracking to identify device/browser
func UserAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		ctx := identity.WithUserAgent(r.Context(), ua)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
