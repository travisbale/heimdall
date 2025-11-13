package http

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/sdk"
)

// issueTokens creates JWT token pair and stores refresh token in HTTP-only cookie
// Access token returned in response body, refresh token in secure cookie to prevent XSS attacks
func issueTokens(ctx context.Context, w http.ResponseWriter, r *http.Request, userService userService, jwtService jwtService, userID, tenantID uuid.UUID, secureCookies bool) {
	scopes, err := userService.GetScopes(ctx, userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to retrieve scopes for user", err)
		return
	}

	accessToken, err := jwtService.IssueAccessToken(userID, tenantID, scopes)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate access token", err)
		return
	}

	refreshToken, err := jwtService.IssueRefreshToken(userID, tenantID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate refresh token", err)
		return
	}

	refreshExpiration := int(jwtService.GetRefreshTokenExpiration().Seconds())

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
		Secure:   secureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	respondJSON(w, http.StatusOK, sdk.LoginResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessTokenExpiry,
	})
}
