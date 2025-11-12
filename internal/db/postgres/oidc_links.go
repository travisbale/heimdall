package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/travisbale/heimdall/internal/auth"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
)

// OAuthLinksDB handles OAuth link database operations
type OIDCLinksDB struct {
	db *DB
}

// NewOIDCLinksDB creates a new OIDCLinksDB instance
func NewOIDCLinksDB(db *DB) *OIDCLinksDB {
	return &OIDCLinksDB{db: db}
}

// CreateOIDCLink creates a new OAuth link between a user and provider
func (o *OIDCLinksDB) CreateOIDCLink(ctx context.Context, link *auth.OIDCLink) (*auth.OIDCLink, error) {
	var result *auth.OIDCLink

	// OAuth links don't use tenant context since they link users to external providers
	err := o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		metadataJSON, err := json.Marshal(link.ProviderMetadata)
		if err != nil {
			return fmt.Errorf("failed to marshal provider metadata: %w", err)
		}

		dbLink, err := q.CreateOIDCLink(ctx, sqlc.CreateOIDCLinkParams{
			UserID:           link.UserID,
			OidcProviderID:   link.OIDCProviderID,
			ProviderUserID:   link.ProviderUserID,
			ProviderEmail:    link.ProviderEmail,
			ProviderMetadata: metadataJSON,
		})
		if err != nil {
			// Check for unique constraint violations
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				if pgErr.ConstraintName == "oauth_links_user_id_provider_type_key" {
					return auth.ErrOIDCLinkAlreadyExists
				}
				if pgErr.ConstraintName == "oauth_links_provider_type_provider_user_id_key" {
					return auth.ErrOIDCProviderAccountAlreadyLinked
				}
			}
			return fmt.Errorf("failed to create oauth link: %w", err)
		}

		result, err = convertOIDCLinkToDomain(dbLink)
		return err
	})

	return result, err
}

// GetOIDCLinkByProvider retrieves an OAuth link by provider ID and provider user ID
func (o *OIDCLinksDB) GetOIDCLinkByProvider(ctx context.Context, providerID uuid.UUID, providerUserID string) (*auth.OIDCLink, error) {
	var result *auth.OIDCLink

	err := o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbLink, err := q.GetOIDCLinkByProvider(ctx, sqlc.GetOIDCLinkByProviderParams{
			OidcProviderID: providerID,
			ProviderUserID: providerUserID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrOIDCLinkNotFound
			}
			return fmt.Errorf("failed to get oauth link by provider: %w", err)
		}

		result, err = convertOIDCLinkToDomain(dbLink)
		return err
	})

	return result, err
}

// GetOIDCLinkByUser retrieves an OAuth link by user ID and provider ID
func (o *OIDCLinksDB) GetOIDCLinkByUser(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) (*auth.OIDCLink, error) {
	var result *auth.OIDCLink

	err := o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbLink, err := q.GetOIDCLinkByUser(ctx, sqlc.GetOIDCLinkByUserParams{
			UserID:         userID,
			OidcProviderID: providerID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrOIDCLinkNotFound
			}
			return fmt.Errorf("failed to get oauth link by user: %w", err)
		}

		result, err = convertOIDCLinkToDomain(dbLink)
		return err
	})

	return result, err
}

// ListOIDCLinksByUser lists all OAuth links for a user
func (o *OIDCLinksDB) ListOIDCLinksByUser(ctx context.Context, userID uuid.UUID) ([]*auth.OIDCLink, error) {
	var result []*auth.OIDCLink

	err := o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbLinks, err := q.ListOIDCLinksByUser(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to list oauth links by user: %w", err)
		}

		result = make([]*auth.OIDCLink, len(dbLinks))
		for i, dbLink := range dbLinks {
			link, err := convertOIDCLinkToDomain(dbLink)
			if err != nil {
				return err
			}
			result[i] = link
		}
		return nil
	})

	return result, err
}

// UpdateOIDCLinkLastUsed updates the last_used_at timestamp
func (o *OIDCLinksDB) UpdateOIDCLinkLastUsed(ctx context.Context, id uuid.UUID) error {
	return o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.UpdateOIDCLinkLastUsed(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to update oauth link last used: %w", err)
		}
		return nil
	})
}

// DeleteOIDCLink deletes an OAuth link by ID
func (o *OIDCLinksDB) DeleteOIDCLink(ctx context.Context, id uuid.UUID) error {
	return o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteOIDCLink(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to delete oauth link: %w", err)
		}
		return nil
	})
}

// DeleteOIDCLinkByUserAndProvider deletes an OAuth link by user ID and provider ID
func (o *OIDCLinksDB) DeleteOIDCLinkByUserAndProvider(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) error {
	return o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteOIDCLinkByUserAndProvider(ctx, sqlc.DeleteOIDCLinkByUserAndProviderParams{
			UserID:         userID,
			OidcProviderID: providerID,
		})
		if err != nil {
			return fmt.Errorf("failed to delete oauth link by user and provider: %w", err)
		}
		return nil
	})
}

// convertOIDCLinkToDomain converts a database OAuthLink to a domain OAuthLink
func convertOIDCLinkToDomain(dbLink sqlc.OidcLink) (*auth.OIDCLink, error) {
	var metadata map[string]any
	if len(dbLink.ProviderMetadata) > 0 {
		if err := json.Unmarshal(dbLink.ProviderMetadata, &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal provider metadata: %w", err)
		}
	}

	return &auth.OIDCLink{
		ID:               dbLink.ID,
		UserID:           dbLink.UserID,
		OIDCProviderID:   dbLink.OidcProviderID,
		ProviderUserID:   dbLink.ProviderUserID,
		ProviderEmail:    dbLink.ProviderEmail,
		ProviderMetadata: metadata,
		LinkedAt:         dbLink.LinkedAt,
		LastUsedAt:       dbLink.LastUsedAt,
	}, nil
}
