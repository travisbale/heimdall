-- name: CreateOIDCProvider :one
INSERT INTO oidc_providers (
    tenant_id,
    provider_name,
    issuer_url,
    client_id,
    client_secret,
    scopes,
    enabled,
    allowed_domains,
    auto_create_users,
    require_email_verification,
    registration_access_token,
    registration_client_uri,
    client_id_issued_at,
    client_secret_expires_at,
    registration_method
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
) RETURNING *;

-- name: GetOIDCProvider :one
SELECT * FROM oidc_providers
WHERE id = $1;

-- name: ListOIDCProviders :many
SELECT * FROM oidc_providers
WHERE tenant_id = $1 AND enabled = true
ORDER BY provider_name;

-- name: UpdateOIDCProvider :one
-- Allows updating configuration and credentials
UPDATE oidc_providers
SET
    provider_name = COALESCE(sqlc.narg('provider_name'), provider_name),
    client_secret = COALESCE(sqlc.narg('client_secret'), client_secret),
    scopes = COALESCE(sqlc.narg('scopes'), scopes),
    enabled = COALESCE(sqlc.narg('enabled'), enabled),
    allowed_domains = COALESCE(sqlc.narg('allowed_domains'), allowed_domains),
    auto_create_users = COALESCE(sqlc.narg('auto_create_users'), auto_create_users),
    require_email_verification = COALESCE(sqlc.narg('require_email_verification'), require_email_verification),
    updated_at = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: DeleteOIDCProvider :exec
DELETE FROM oidc_providers
WHERE id = $1;

-- name: GetOIDCProvidersByDomain :many
-- Find all OAuth providers configured for an email domain (cross-tenant, for SSO discovery)
-- This query bypasses RLS to search across all tenants
SELECT * FROM oidc_providers
WHERE enabled = true
  AND $1 = ANY(allowed_domains)
ORDER BY created_at ASC;
