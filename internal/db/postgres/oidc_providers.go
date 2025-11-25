package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/travisbale/heimdall/crypto/aes"
	"github.com/travisbale/heimdall/identity"
	"github.com/travisbale/heimdall/internal/db/postgres/internal/sqlc"
	"github.com/travisbale/heimdall/internal/iam"
)

// OIDCProvidersDB manages tenant-specific OIDC provider configs with encrypted secrets
type OIDCProvidersDB struct {
	db     *DB
	cipher *aes.Cipher
}

func NewOIDCProvidersDB(db *DB, cipher *aes.Cipher) *OIDCProvidersDB {
	return &OIDCProvidersDB{
		db:     db,
		cipher: cipher,
	}
}

// CreateOIDCProvider stores provider config with AES-256-GCM encrypted client secret
func (o *OIDCProvidersDB) CreateOIDCProvider(ctx context.Context, provider *iam.OIDCProviderConfig) (*iam.OIDCProviderConfig, error) {
	var result *iam.OIDCProviderConfig

	err := o.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		tenantID, err := identity.GetTenant(ctx)
		if err != nil {
			return err
		}

		// Encrypt client secret at rest to protect OAuth credentials
		encryptedSecret, err := o.cipher.Encrypt(provider.ClientSecret)
		if err != nil {
			return fmt.Errorf("failed to encrypt client secret: %w", err)
		}

		dbProvider, err := q.CreateOIDCProvider(ctx, sqlc.CreateOIDCProviderParams{
			TenantID:                 tenantID,
			ProviderName:             provider.ProviderName,
			IssuerUrl:                provider.IssuerURL,
			ClientID:                 provider.ClientID,
			ClientSecret:             encryptedSecret,
			Scopes:                   provider.Scopes,
			Enabled:                  provider.Enabled,
			AllowedDomains:           provider.AllowedDomains,
			AutoCreateUsers:          provider.AutoCreateUsers,
			RequireEmailVerification: provider.RequireEmailVerification,
			RegistrationAccessToken:  provider.RegistrationAccessToken,
			RegistrationClientUri:    provider.RegistrationClientURI,
			ClientIDIssuedAt:         provider.ClientIDIssuedAt,
			ClientSecretExpiresAt:    provider.ClientSecretExpiresAt,
			RegistrationMethod:       provider.RegistrationMethod,
		})
		if err != nil {
			return fmt.Errorf("failed to create oauth provider: %w", err)
		}

		result, err = o.convertOIDCProviderToDomain(dbProvider)
		return err
	})

	return result, err
}

// GetOIDCProviderByID retrieves provider by ID with optional tenant validation
func (o *OIDCProvidersDB) GetOIDCProviderByID(ctx context.Context, id uuid.UUID) (*iam.OIDCProviderConfig, error) {
	var result *iam.OIDCProviderConfig

	err := o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbProvider, err := q.GetOIDCProvider(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return iam.ErrOIDCProviderNotFound
			}
			return fmt.Errorf("failed to get oauth provider by id: %w", err)
		}

		// Tenant validation if context has tenant
		if tenantID, err := identity.GetTenant(ctx); err == nil {
			if dbProvider.TenantID != tenantID {
				return iam.ErrOIDCProviderNotFound
			}
		}

		result, err = o.convertOIDCProviderToDomain(dbProvider)
		return err
	})

	return result, err
}

// ListOIDCProviders lists all enabled OAuth providers for the tenant
func (o *OIDCProvidersDB) ListOIDCProviders(ctx context.Context) ([]*iam.OIDCProviderConfig, error) {
	var result []*iam.OIDCProviderConfig

	err := o.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		tenantID, err := identity.GetTenant(ctx)
		if err != nil {
			return err
		}

		dbProviders, err := q.ListOIDCProviders(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("failed to list oauth providers: %w", err)
		}

		result = make([]*iam.OIDCProviderConfig, len(dbProviders))
		for i, dbProvider := range dbProviders {
			provider, err := o.convertOIDCProviderToDomain(dbProvider)
			if err != nil {
				return fmt.Errorf("failed to convert provider: %w", err)
			}
			result[i] = provider
		}
		return nil
	})

	return result, err
}

// UpdateOIDCProvider updates an OAuth provider
// Fields in params that are pointers (nil) or empty slices will not be updated (COALESCE in SQL)
func (o *OIDCProvidersDB) UpdateOIDCProvider(ctx context.Context, params *iam.UpdateOIDCProviderParams) (*iam.OIDCProviderConfig, error) {
	var result *iam.OIDCProviderConfig

	err := o.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		// Encrypt client secret if provided
		var encryptedSecret *string
		if params.ClientSecret != nil {
			encrypted, err := o.cipher.Encrypt(*params.ClientSecret)
			if err != nil {
				return fmt.Errorf("failed to encrypt client secret: %w", err)
			}
			encryptedSecret = &encrypted
		}

		sqlcParams := sqlc.UpdateOIDCProviderParams{
			ID:                       params.ID,
			ProviderName:             params.ProviderName,
			ClientSecret:             encryptedSecret,
			Scopes:                   params.Scopes,
			Enabled:                  params.Enabled,
			AllowedDomains:           params.AllowedDomains,
			AutoCreateUsers:          params.AutoCreateUsers,
			RequireEmailVerification: params.RequireEmailVerification,
		}

		dbProvider, err := q.UpdateOIDCProvider(ctx, sqlcParams)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return iam.ErrOIDCProviderNotFound
			}
			return fmt.Errorf("failed to update oauth provider: %w", err)
		}

		result, err = o.convertOIDCProviderToDomain(dbProvider)
		return err
	})

	return result, err
}

// DeleteOIDCProviderByID deletes an OAuth provider by ID
func (o *OIDCProvidersDB) DeleteOIDCProviderByID(ctx context.Context, id uuid.UUID) error {
	return o.db.WithTenantContext(ctx, func(q *sqlc.Queries) error {
		err := q.DeleteOIDCProvider(ctx, id)
		if err != nil {
			return fmt.Errorf("failed to delete oauth provider: %w", err)
		}
		return nil
	})
}

// GetOIDCProvidersByDomain retrieves all OAuth providers configured for an email domain
// This is used for SSO discovery during login (cross-tenant, pre-authentication)
func (o *OIDCProvidersDB) GetOIDCProvidersByDomain(ctx context.Context, domain string) ([]*iam.OIDCProviderConfig, error) {
	var result []*iam.OIDCProviderConfig

	// Domain-based lookup doesn't use tenant context (pre-authentication)
	// Uses WithTransaction to bypass RLS and search across all tenants
	err := o.db.WithTransaction(ctx, func(q *sqlc.Queries) error {
		dbProviders, err := q.GetOIDCProvidersByDomain(ctx, domain)
		if err != nil {
			return fmt.Errorf("failed to get oauth providers by domain: %w", err)
		}

		result = make([]*iam.OIDCProviderConfig, len(dbProviders))
		for i, dbProvider := range dbProviders {
			provider, err := o.convertOIDCProviderToDomain(dbProvider)
			if err != nil {
				return fmt.Errorf("failed to convert provider: %w", err)
			}
			result[i] = provider
		}
		return nil
	})

	return result, err
}

// convertOIDCProviderToDomain converts a database OAuthProvider to a domain OAuthProvider
func (o *OIDCProvidersDB) convertOIDCProviderToDomain(dbProvider sqlc.OidcProvider) (*iam.OIDCProviderConfig, error) {
	// Decrypt the client secret
	decryptedSecret, err := o.cipher.Decrypt(dbProvider.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt client secret: %w", err)
	}

	return &iam.OIDCProviderConfig{
		ID:                       dbProvider.ID,
		TenantID:                 dbProvider.TenantID,
		ProviderName:             dbProvider.ProviderName,
		IssuerURL:                dbProvider.IssuerUrl,
		ClientID:                 dbProvider.ClientID,
		ClientSecret:             decryptedSecret,
		Scopes:                   dbProvider.Scopes,
		Enabled:                  dbProvider.Enabled,
		AllowedDomains:           dbProvider.AllowedDomains,
		AutoCreateUsers:          dbProvider.AutoCreateUsers,
		RequireEmailVerification: dbProvider.RequireEmailVerification,
		RegistrationAccessToken:  dbProvider.RegistrationAccessToken,
		RegistrationClientURI:    dbProvider.RegistrationClientUri,
		ClientIDIssuedAt:         dbProvider.ClientIDIssuedAt,
		ClientSecretExpiresAt:    dbProvider.ClientSecretExpiresAt,
		RegistrationMethod:       dbProvider.RegistrationMethod,
	}, nil
}
