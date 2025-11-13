package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/sdk"
)

// OIDCSessionsDB manages OAuth flow sessions (state, PKCE, provider tracking)
type OIDCSessionsDB struct {
	db *DB
}

func NewOIDCSessionsDB(db *DB) *OIDCSessionsDB {
	return &OIDCSessionsDB{db: db}
}

// CreateOIDCSession creates temporary session for OAuth flow (CSRF protection via state)
func (o *OIDCSessionsDB) CreateOIDCSession(ctx context.Context, session *auth.OIDCSession) (*auth.OIDCSession, error) {
	var result *auth.OIDCSession

	err := o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		// Convert ProviderType pointer to NullOidcProviderType
		var providerType sqlc.NullOidcProviderType
		if session.ProviderType != nil {
			providerType = sqlc.NullOidcProviderType{
				OidcProviderType: sqlc.OidcProviderType(*session.ProviderType),
				Valid:            true,
			}
		}

		dbSession, err := q.CreateOIDCSession(ctx, sqlc.CreateOIDCSessionParams{
			State:          session.State,
			CodeVerifier:   session.CodeVerifier,
			OidcProviderID: session.OIDCProviderID,
			ProviderType:   providerType,
			RedirectUri:    session.RedirectURI,
			TenantID:       session.TenantID,
			ExpiresAt:      session.ExpiresAt,
		})
		if err != nil {
			return fmt.Errorf("failed to create oauth session: %w", err)
		}

		result = convertOIDCSessionToDomain(dbSession)
		return nil
	})

	return result, err
}

// GetOIDCSessionByState retrieves session by state parameter (validates CSRF token)
func (o *OIDCSessionsDB) GetOIDCSessionByState(ctx context.Context, state string) (*auth.OIDCSession, error) {
	var result *auth.OIDCSession

	err := o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbSession, err := q.GetOIDCSessionByState(ctx, state)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrOIDCSessionNotFound
			}
			return fmt.Errorf("failed to get oauth session by state: %w", err)
		}

		result = convertOIDCSessionToDomain(dbSession)
		return nil
	})

	return result, err
}

// DeleteOIDCSession deletes an OAuth session by ID
func (o *OIDCSessionsDB) DeleteOIDCSession(ctx context.Context, id uuid.UUID) error {
	return o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteOIDCSession(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to delete oauth session: %w", err)
		}
		return nil
	})
}

// DeleteExpiredOIDCSessions deletes all expired OAuth sessions
func (o *OIDCSessionsDB) DeleteExpiredOIDCSessions(ctx context.Context) error {
	return o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteExpiredOIDCSessions(ctx)
		if err != nil {
			return fmt.Errorf("failed to delete expired oauth sessions: %w", err)
		}
		return nil
	})
}

// convertOIDCSessionToDomain converts a database OAuthSession to a domain OAuthSession
func convertOIDCSessionToDomain(dbSession sqlc.OidcSession) *auth.OIDCSession {
	// Convert NullOidcProviderType to pointer
	var providerType *sdk.OIDCProviderType
	if dbSession.ProviderType.Valid {
		pt := sdk.OIDCProviderType(dbSession.ProviderType.OidcProviderType)
		providerType = &pt
	}

	return &auth.OIDCSession{
		ID:             dbSession.ID,
		State:          dbSession.State,
		CodeVerifier:   dbSession.CodeVerifier,
		OIDCProviderID: dbSession.OidcProviderID,
		ProviderType:   providerType,
		RedirectURI:    dbSession.RedirectUri,
		TenantID:       dbSession.TenantID,
		CreatedAt:      dbSession.CreatedAt,
		ExpiresAt:      dbSession.ExpiresAt,
	}
}
