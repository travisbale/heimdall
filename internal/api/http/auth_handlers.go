package http

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/sdk"
)

const refreshTokenCookie = "refresh_token"

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	userService      userService
	rbacService      rbacService
	jwtService       jwtService
	secureCookies    bool // Secure flag prevents cookies from being sent over HTTP (only HTTPS)
	trustedProxyMode bool // Enable IP extraction from X-Forwarded-For when behind trusted reverse proxy
	logger           logger
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(config *Config) *AuthHandler {
	return &AuthHandler{
		userService:      config.UserService,
		rbacService:      config.RBACService,
		jwtService:       config.JWTService,
		secureCookies:    config.SecureCookies(),
		trustedProxyMode: config.TrustedProxyMode,
		logger:           config.Logger,
	}
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req sdk.LoginRequest
	if !decodeAndValidateJSON(w, r, &req) {
		return
	}

	user, err := h.userService.Login(r.Context(), req.Email, req.Password, h.extractIPAddress(r))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			respondError(w, http.StatusUnauthorized, "Authentication failed", err)

		case errors.Is(err, auth.ErrEmailNotVerified):
			respondError(w, http.StatusForbidden, "Please verify your email address before logging in", err)

		case errors.Is(err, auth.ErrAccountLocked):
			respondError(w, http.StatusTooManyRequests, "Too many failed login attempts. Please try again later.", err)

		default:
			respondError(w, http.StatusInternalServerError, "Failed to authenticate user", err)
		}
		return
	}

	issueTokens(r.Context(), w, r, h.rbacService, h.jwtService, user.ID, user.TenantID, h.secureCookies)
}

// Logout handles user logout by clearing the refresh token cookie
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Construct cookie path using X-Forwarded-Prefix if available
	prefix := r.Header.Get("X-Forwarded-Prefix")
	cookiePath := prefix + sdk.RouteV1Refresh

	// Clear the refresh token cookie by setting MaxAge to -1
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    "",
		Path:     cookiePath,
		MaxAge:   -1, // Deletes the cookie
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	respondJSON(w, http.StatusOK, sdk.LogoutResponse{
		Message: "Logged out successfully",
	})
}

// RefreshToken handles token refresh using the refresh token from HTTP-only cookie
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Read refresh token from HTTP-only cookie
	cookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Missing refresh token", err)
		return
	}

	claims, err := h.jwtService.ValidateToken(cookie.Value)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid or expired refresh token", err)
		return
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to parse user ID", err)
		return
	}

	issueTokens(r.Context(), w, r, h.rbacService, h.jwtService, userID, claims.TenantID, h.secureCookies)
}

// extractIPAddress extracts the client IP address from the request with security validation
func (h *AuthHandler) extractIPAddress(r *http.Request) string {
	// Behind trusted reverse proxy - extract from proxy headers
	if h.trustedProxyMode {
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

		if net.ParseIP(ip) != nil {
			return ip
		}

		h.logger.Warn("invalid IP from proxy header, falling back to RemoteAddr",
			"invalid_ip", ip,
			"x_forwarded_for", r.Header.Get("X-Forwarded-For"),
			"x_real_ip", r.Header.Get("X-Real-IP"),
		)
	}

	// Use RemoteAddr if no valid proxy IP (or not in proxy mode)
	return stripPort(r.RemoteAddr)
}

// stripPort removes the port from an address string (e.g., "192.168.1.1:8080" -> "192.168.1.1")
func stripPort(addr string) string {
	// For IPv6 addresses like "[::1]:8080", handle brackets
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}

	return addr
}
