package http

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/sdk"
)

// respondJSON sends JSON response with given status code
func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.ErrorContext(context.Background(), "Failed to encode JSON response", "error", err)
	}
}

// decodeJSON decodes JSON from request body, rejects unknown fields
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close() //nolint:errcheck

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Catch typos in client requests

	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}

	return nil
}

// validator is an interface for types that can validate themselves
type validator interface {
	Validate(ctx context.Context) error
}

// decodeAndValidateJSON decodes and validates JSON, returns false if error response was sent
func decodeAndValidateJSON(w http.ResponseWriter, r *http.Request, req validator) bool {
	if err := decodeJSON(r, req); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: "Invalid request body"})
		return false
	}

	if err := req.Validate(r.Context()); err != nil {
		respondJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: err.Error()})
		return false
	}

	return true
}

// getAuthenticatedUserID extracts the user ID from context, returns false if unauthorized
func getAuthenticatedUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	userID, err := identity.GetUser(r.Context())
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sdk.ErrorResponse{Error: "Unauthorized"})
		return uuid.Nil, false
	}
	return userID, true
}

// parseUUID parses UUID from string, returns uuid.Nil on invalid input
func parseUUID(s string) uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// encodeSessionResponse encodes session tokens into HTTP response (cookies + JSON)
func encodeSessionResponse(w http.ResponseWriter, r *http.Request, tokens *iam.SessionTokens, secureCookies bool) {
	// MFA setup required - user's role requires MFA but they haven't set it up yet
	if tokens.RequiresMFASetup() {
		respondJSON(w, http.StatusOK, sdk.LoginResponse{
			MFASetupToken: tokens.MFASetupToken,
			ExpiresIn:     int(tokens.MFASetupExpiration.Seconds()),
		})
		return
	}

	// MFA verification required - user has MFA enabled
	if tokens.RequiresMFA() {
		respondJSON(w, http.StatusOK, sdk.LoginResponse{
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

	respondJSON(w, http.StatusOK, sdk.LoginResponse{
		AccessToken: tokens.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(tokens.AccessExpiration.Seconds()),
	})
}
