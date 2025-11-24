package http

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/sdk"
)

// Subject represents the identity for which tokens are issued
type Subject struct {
	UserID      uuid.UUID
	TenantID    uuid.UUID
	MFARequired bool
}

// TokenService handles JWT token issuance and HTTP response
type TokenService struct {
	rbacService   rbacService
	jwtService    jwtService
	secureCookies bool
}

// NewTokenService creates a new TokenService
func NewTokenService(rbacService rbacService, jwtService jwtService, secureCookies bool) *TokenService {
	return &TokenService{
		rbacService:   rbacService,
		jwtService:    jwtService,
		secureCookies: secureCookies,
	}
}

// IssueTokens creates JWT token pair and stores refresh token in HTTP-only cookie
func (s *TokenService) IssueTokens(ctx context.Context, w http.ResponseWriter, r *http.Request, subject *Subject) {
	if subject.MFARequired {
		challengeToken, err := s.jwtService.IssueMFAChallengeToken(subject.UserID, subject.TenantID)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to generate MFA challenge token"})
			return
		}

		// User must complete MFA to get full access
		respondJSON(w, http.StatusOK, sdk.LoginResponse{
			MFAChallengeToken: challengeToken,
			ExpiresIn:         int(s.jwtService.GetMFAChallengeTokenExpiration().Seconds()),
		})
		return
	}

	// User is fully authenticated - issue regular access/refresh token pair
	ctx = identity.WithUser(ctx, subject.UserID, subject.TenantID)
	scopes, err := s.rbacService.GetUserScopes(ctx, subject.UserID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to retrieve scopes for user"})
		return
	}

	accessToken, err := s.jwtService.IssueAccessToken(subject.TenantID, subject.UserID, scopes)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to generate access token"})
		return
	}

	refreshToken, err := s.jwtService.IssueRefreshToken(subject.TenantID, subject.UserID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to generate refresh token"})
		return
	}

	accessExpiration := int(s.jwtService.GetAccessTokenExpiration().Seconds())
	refreshExpiration := int(s.jwtService.GetRefreshTokenExpiration().Seconds())

	// X-Forwarded-Prefix support for reverse proxy deployments
	prefix := r.Header.Get("X-Forwarded-Prefix")
	cookiePath := prefix + sdk.RouteV1Refresh

	// HttpOnly prevents JavaScript access, Secure requires HTTPS, SameSite prevents CSRF
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    refreshToken,
		Path:     cookiePath,
		MaxAge:   refreshExpiration,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	respondJSON(w, http.StatusOK, sdk.LoginResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessExpiration,
	})
}

// RefreshToken validates a refresh token from HTTP-only cookie and issues new token pair
func (s *TokenService) RefreshToken(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	// Read refresh token from HTTP-only cookie
	cookie, err := r.Cookie(refreshTokenCookie)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Missing refresh token"})
		return
	}

	claims, err := s.jwtService.ValidateToken(cookie.Value)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Invalid or expired refresh token"})
		return
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, sdk.ErrorResponse{Error: "Failed to parse user ID"})
		return
	}

	// MFA not required for refresh (user already authenticated)
	s.IssueTokens(ctx, w, r, &Subject{
		UserID:      userID,
		TenantID:    claims.TenantID,
		MFARequired: false,
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
