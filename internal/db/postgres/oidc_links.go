package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/internal/iam"
)

// OIDCLinksDB manages user-to-provider links for SSO (tracks by provider's sub claim)
type OIDCLinksDB struct {
	db *DB
}

func NewOIDCLinksDB(db *DB) *OIDCLinksDB {
	return &OIDCLinksDB{db: db}
}

// CreateOIDCLink creates link between user and provider (tracks by immutable sub claim)
func (o *OIDCLinksDB) CreateOIDCLink(ctx context.Context, link *iam.OIDCLink) (*iam.OIDCLink, error) {
	var result *iam.OIDCLink

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
			// Convert unique constraint violations to domain errors
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				if pgErr.ConstraintName == "oidc_links_user_id_oidc_provider_id_key" {
					return iam.ErrOIDCLinkAlreadyExists
				}
				if pgErr.ConstraintName == "oidc_links_oidc_provider_id_provider_user_id_key" {
					return iam.ErrOIDCProviderAccountAlreadyLinked
				}
			}
			return fmt.Errorf("failed to create oidc link: %w", err)
		}

		result, err = convertOIDCLinkToDomain(dbLink)
		return err
	})

	return result, err
}

// GetOIDCLinkByProvider retrieves link by provider's sub claim (allows email reassignment)
func (o *OIDCLinksDB) GetOIDCLinkByProvider(ctx context.Context, providerID uuid.UUID, providerUserID string) (*iam.OIDCLink, error) {
	var result *iam.OIDCLink

	err := o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbLink, err := q.GetOIDCLinkByProvider(ctx, sqlc.GetOIDCLinkByProviderParams{
			OidcProviderID: providerID,
			ProviderUserID: providerUserID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return iam.ErrOIDCLinkNotFound
			}
			return fmt.Errorf("failed to get oidc link by provider: %w", err)
		}

		result, err = convertOIDCLinkToDomain(dbLink)
		return err
	})

	return result, err
}

// GetOIDCLinkByUser retrieves an OIDC link by user ID and provider ID
func (o *OIDCLinksDB) GetOIDCLinkByUser(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) (*iam.OIDCLink, error) {
	var result *iam.OIDCLink

	err := o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbLink, err := q.GetOIDCLinkByUser(ctx, sqlc.GetOIDCLinkByUserParams{
			UserID:         userID,
			OidcProviderID: providerID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return iam.ErrOIDCLinkNotFound
			}
			return fmt.Errorf("failed to get oidc link by user: %w", err)
		}

		result, err = convertOIDCLinkToDomain(dbLink)
		return err
	})

	return result, err
}

// ListOIDCLinksByUser lists all OIDC links for a user
func (o *OIDCLinksDB) ListOIDCLinksByUser(ctx context.Context, userID uuid.UUID) ([]*iam.OIDCLink, error) {
	var result []*iam.OIDCLink

	err := o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbLinks, err := q.ListOIDCLinksByUser(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to list oidc links by user: %w", err)
		}

		result = make([]*iam.OIDCLink, len(dbLinks))
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
			return fmt.Errorf("failed to update oidc link last used: %w", err)
		}
		return nil
	})
}

// DeleteOIDCLink deletes an OIDC link by user ID and provider ID
func (o *OIDCLinksDB) DeleteOIDCLink(ctx context.Context, userID uuid.UUID, providerID uuid.UUID) error {
	return o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteOIDCLink(ctx, sqlc.DeleteOIDCLinkParams{
			UserID:         userID,
			OidcProviderID: providerID,
		})
		if err != nil {
			return fmt.Errorf("failed to delete oidc link: %w", err)
		}
		return nil
	})
}

// convertOIDCLinkToDomain converts a database OIDCLink to a domain OIDCLink
func convertOIDCLinkToDomain(dbLink sqlc.OidcLink) (*iam.OIDCLink, error) {
	var metadata map[string]any
	if len(dbLink.ProviderMetadata) > 0 {
		if err := json.Unmarshal(dbLink.ProviderMetadata, &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal provider metadata: %w", err)
		}
	}

	return &iam.OIDCLink{
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
