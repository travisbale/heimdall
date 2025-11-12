package http

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// issueTokens sets the refresh token cookie, and responds with the access token
func issueTokens(ctx context.Context, w http.ResponseWriter, r *http.Request, userService userService, jwtService jwtService, userID, tenantID uuid.UUID, secureCookies bool) {
	// Get user scopes
	scopes, err := userService.GetScopes(ctx, userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve scopes for user", err)
		return
	}

	// Issue access token
	accessToken, err := jwtService.IssueAccessToken(userID, tenantID, scopes)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate access token", err)
		return
	}

	// Issue refresh token
	refreshToken, err := jwtService.IssueRefreshToken(userID, tenantID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate refresh token", err)
		return
	}

	// Get refresh token expiration from JWT service
	refreshExpiration := int(jwtService.GetRefreshTokenExpiration().Seconds())

	// Construct cookie path using X-Forwarded-Prefix if available
	prefix := r.Header.Get("X-Forwarded-Prefix")
	cookiePath := prefix + sdk.RouteV1Refresh

	// Set refresh token in HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    refreshToken,
		Path:     cookiePath,
		MaxAge:   refreshExpiration,
		HttpOnly: true,
		Secure:   secureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	// Return access token in response body
	respondJSON(w, http.StatusOK, sdk.LoginResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessTokenExpiry,
	})
}
