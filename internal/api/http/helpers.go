package http

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// issueTokensAndRespond is a helper function that issues JWT tokens, sets the refresh token cookie,
// and responds with the access token. This is used by both login and email verification endpoints.
func issueTokensAndRespond(ctx context.Context, w http.ResponseWriter, userService userService, jwtService jwtService, userID, tenantID uuid.UUID, secureCookies bool, refreshExpiration int) {
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

	// Set refresh token in HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    refreshToken,
		Path:     "/v1/refresh",
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
