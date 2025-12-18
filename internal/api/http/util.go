package http

import (
	"net/http"

	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/api"
)

const (
	refreshTokenCookie = "refresh_token"
	deviceTrustCookie  = "device_trust"
)

// encodeSessionResponse encodes session tokens into HTTP response (cookies + JSON)
func encodeSessionResponse(w http.ResponseWriter, r *http.Request, tokens *iam.SessionTokens, secureCookies bool) {
	// MFA setup required - user's role requires MFA but they haven't set it up yet
	if tokens.RequiresMFASetup() {
		api.RespondJSON(w, http.StatusOK, sdk.LoginResponse{
			MFASetupToken: tokens.MFASetupToken,
			ExpiresIn:     int(tokens.MFASetupExpiration.Seconds()),
		})
		return
	}

	// MFA verification required - user has MFA enabled
	if tokens.RequiresMFA() {
		api.RespondJSON(w, http.StatusOK, sdk.LoginResponse{
			MFAChallengeToken: tokens.MFAChallengeToken,
			ExpiresIn:         int(tokens.MFAChallengeExpiration.Seconds()),
		})
		return
	}

	// X-Forwarded-Prefix support for reverse proxy deployments
	prefix := r.Header.Get("X-Forwarded-Prefix")
	cookiePath := prefix + sdk.RouteV1Refresh

	// HttpOnly prevents JavaScript access, Secure requires HTTPS, SameSite prevents CSRF
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    tokens.RefreshToken,
		Path:     cookiePath,
		MaxAge:   int(tokens.RefreshExpiration.Seconds()),
		HttpOnly: true,
		Secure:   secureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	api.RespondJSON(w, http.StatusOK, sdk.LoginResponse{
		AccessToken: tokens.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(tokens.AccessExpiration.Seconds()),
	})
}
