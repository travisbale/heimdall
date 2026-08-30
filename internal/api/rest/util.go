package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/travisbale/heimdall/internal/iam"
	"github.com/travisbale/heimdall/internal/password"
	"github.com/travisbale/heimdall/sdk"
	"github.com/travisbale/knowhere/identity"
)

const (
	refreshTokenCookie = "refresh_token"
	deviceTrustCookie  = "device_trust"
)

// maxRequestBody caps decoded request bodies to guard against a client streaming an
// unbounded payload into memory. Registration and sign-in decode from anyone.
const maxRequestBody = 1 << 20 // 1 MiB

type validatable interface {
	Validate(ctx context.Context) error
}

func (r *Router) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		r.Logger.Error("Failed to encode JSON response", "error", err, "status", status)
	}
}

// serverFault is the only thing a caller is told when the fault is ours. Naming the
// operation that failed tells them nothing they can act on and reads as a verdict on
// their request — "Failed to verify email" sounds like the address was rejected.
const serverFault = "Sorry, something went wrong. Please try again later."

// The message a caller passes for a 5xx describes the operation, so it is kept as the log
// line and replaced on the wire.
func (r *Router) writeError(ctx context.Context, w http.ResponseWriter, status int, message string, err error) {
	if status >= http.StatusInternalServerError {
		r.Logger.ErrorContext(ctx, message, "error", err, "status", status)
		message = serverFault
	} else if err != nil {
		// Client errors log at Warn so a bad request does not pollute the error stream.
		r.Logger.WarnContext(ctx, message, "error", err, "status", status)
	}

	r.writeJSON(w, status, sdk.ErrorResponse{Error: message})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	defer r.Body.Close() //nolint:errcheck

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func (r *Router) decodeAndValidateJSON(w http.ResponseWriter, req *http.Request, v validatable) bool {
	if err := decodeJSON(w, req, v); err != nil {
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

// passwordRejection is the wording a client gets; the validator's own errors stay internal.
func passwordRejection(err error) string {
	switch {
	case errors.Is(err, password.ErrTooShort):
		return fmt.Sprintf("Password must be at least %d characters", password.MinLength)
	case errors.Is(err, password.ErrTooLong):
		return fmt.Sprintf("Password must not exceed %d characters", password.MaxLength)
	case errors.Is(err, password.ErrTooCommon):
		return "Password is too common, please choose a less predictable one"
	case errors.Is(err, password.ErrBreached):
		return "Password has appeared in a known data breach, please choose another"
	default:
		return "Password does not meet the requirements"
	}
}

// accountDeactivated is what a refused sign-in is told, wherever it was refused. Every door
// gives the same answer because they are the same refusal, and a caller comparing two of
// them should find nothing to tell them apart.
const accountDeactivated = "This account is no longer active. Please contact your administrator."

// roleNameTaken is what both doors that name a role say, for the same reason accountDeactivated
// is one constant: the same refusal should not be able to drift into two sentences.
const roleNameTaken = "A role with this name already exists"
