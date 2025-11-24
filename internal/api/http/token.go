package http

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/sdk"
)

// TokenService encodes session tokens into HTTP responses
type TokenService struct {
	sessionService sessionService
	secureCookies  bool
}

// NewTokenService creates a new TokenService
func NewTokenService(sessionService sessionService, secureCookies bool) *TokenService {
	return &TokenService{
		sessionService: sessionService,
		secureCookies:  secureCookies,
	}
}

// IssueTokens creates session tokens and encodes them into HTTP response
func (s *TokenService) IssueTokens(ctx context.Context, w http.ResponseWriter, r *http.Request, tenantID, userID uuid.UUID, checkMFA bool) {
	ctx = identity.WithTenant(ctx, tenantID)

	// Generate session tokens via auth layer
	tokens, err := s.sessionService.CreateSession(ctx, tenantID, userID, checkMFA)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to create session"})
		return
	}

	// User requires MFA - return challenge token
	if tokens.RequiresMFA {
		respondJSON(w, http.StatusOK, sdk.LoginResponse{
			MFAChallengeToken: tokens.MFAChallengeToken,
			ExpiresIn:         int(tokens.MFAChallengeExpiration.Seconds()),
		})
		return
	}

	// User fully authenticated - encode tokens into response
	accessExpiration := int(tokens.AccessExpiration.Seconds())
	refreshExpiration := int(tokens.RefreshExpiration.Seconds())

	// X-Forwarded-Prefix support for reverse proxy deployments
	prefix := r.Header.Get("X-Forwarded-Prefix")
	cookiePath := prefix + sdk.RouteV1Refresh

	// HttpOnly prevents JavaScript access, Secure requires HTTPS, SameSite prevents CSRF
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    tokens.RefreshToken,
		Path:     cookiePath,
		MaxAge:   refreshExpiration,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	respondJSON(w, http.StatusOK, sdk.LoginResponse{
		AccessToken: tokens.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessExpiration,
	})
}

// RefreshToken validates a refresh token from HTTP-only cookie and issues new token pair
func (s *TokenService) RefreshToken(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Missing refresh token"})
		return
	}

	tokens, err := s.sessionService.RefreshSession(ctx, cookie.Value)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid or expired refresh token"})
		return
	}

	// Encode tokens into HTTP response
	accessExpiration := int(tokens.AccessExpiration.Seconds())
	refreshExpiration := int(tokens.RefreshExpiration.Seconds())

	// X-Forwarded-Prefix support for reverse proxy deployments
	prefix := r.Header.Get("X-Forwarded-Prefix")
	cookiePath := prefix + sdk.RouteV1Refresh

	// HttpOnly prevents JavaScript access, Secure requires HTTPS, SameSite prevents CSRF
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    tokens.RefreshToken,
		Path:     cookiePath,
		MaxAge:   refreshExpiration,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	respondJSON(w, http.StatusOK, sdk.LoginResponse{
		AccessToken: tokens.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessExpiration,
	})
}

// RevokeTokens clears the refresh token cookie to invalidate the session
func (s *TokenService) RevokeTokens(w http.ResponseWriter, r *http.Request) {
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
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	respondJSON(w, http.StatusOK, sdk.LogoutResponse{
		Message: "Logged out successfully",
	})
}
