package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/identity"
)

const (
	refreshTokenCookie = "refresh_token"
	deviceTrustCookie  = "device_trust"
)

type validatable interface {
	Validate(ctx context.Context) error
}

func (r *Router) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (r *Router) writeError(ctx context.Context, w http.ResponseWriter, status int, message string, err error) {
	if status >= http.StatusInternalServerError && err != nil {
		r.Logger.ErrorContext(ctx, message, "error", err, "status", status)
	}

	r.writeJSON(w, status, sdk.ErrorResponse{Error: message})
}

func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close() //nolint:errcheck

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func (r *Router) decodeAndValidateJSON(w http.ResponseWriter, req *http.Request, v validatable) bool {
	if err := decodeJSON(req, v); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, "Invalid request body", nil)
		return false
	}

	if err := v.Validate(req.Context()); err != nil {
		r.writeError(req.Context(), w, http.StatusBadRequest, err.Error(), nil)
		return false
	}

	return true
}

func parseUUID(s string) uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil
	}
	return id
}

func (r *Router) getAuthenticatedActorID(w http.ResponseWriter, req *http.Request) (uuid.UUID, bool) {
	actorID, err := identity.GetActor(req.Context())
	if err != nil {
		r.writeError(req.Context(), w, http.StatusUnauthorized, "Unauthorized", nil)
		return uuid.Nil, false
	}
	return actorID, true
}

func (r *Router) encodeSessionResponse(w http.ResponseWriter, req *http.Request, tokens *iam.SessionTokens) {
	// MFA setup required - user's role requires MFA but they haven't set it up yet
	if tokens.RequiresMFASetup() {
		r.writeJSON(w, http.StatusOK, sdk.LoginResponse{
			MFASetupToken: tokens.MFASetupToken,
			ExpiresIn:     int(tokens.MFASetupExpiration.Seconds()),
		})
		return
	}

	// MFA verification required - user has MFA enabled
	if tokens.RequiresMFA() {
		r.writeJSON(w, http.StatusOK, sdk.LoginResponse{
			MFAChallengeToken: tokens.MFAChallengeToken,
			ExpiresIn:         int(tokens.MFAChallengeExpiration.Seconds()),
		})
		return
	}

	// X-Forwarded-Prefix support for reverse proxy deployments
	prefix := req.Header.Get("X-Forwarded-Prefix")
	cookiePath := prefix + sdk.RouteV1Refresh

	// HttpOnly prevents JavaScript access, Secure requires HTTPS, SameSite prevents CSRF
	http.SetCookie(w, &http.Cookie{
		Name:     refreshTokenCookie,
		Value:    tokens.RefreshToken,
		Path:     cookiePath,
		MaxAge:   int(tokens.RefreshExpiration.Seconds()),
		HttpOnly: true,
		Secure:   r.SecureCookies,
		SameSite: http.SameSiteStrictMode,
	})

	r.writeJSON(w, http.StatusOK, sdk.LoginResponse{
		AccessToken:      tokens.AccessToken,
		TokenType:        "Bearer",
		ExpiresIn:        int(tokens.AccessExpiration.Seconds()),
		RefreshExpiresIn: int(tokens.RefreshExpiration.Seconds()),
	})
}
