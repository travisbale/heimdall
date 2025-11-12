-- name: CreateOIDCLink :one
INSERT INTO oidc_links (
    user_id,
    oidc_provider_id,
    provider_user_id,
    provider_email,
    provider_metadata
) VALUES (
    $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetOIDCLinkByProvider :one
SELECT * FROM oidc_links
WHERE oidc_provider_id = $1 AND provider_user_id = $2;

-- name: GetOIDCLinkByUser :one
SELECT * FROM oidc_links
WHERE user_id = $1 AND oidc_provider_id = $2;

-- name: ListOIDCLinksByUser :many
SELECT * FROM oidc_links
WHERE user_id = $1
ORDER BY linked_at DESC;

-- name: UpdateOIDCLinkLastUsed :exec
UPDATE oidc_links
SET last_used_at = now()
WHERE id = $1;

-- name: DeleteOIDCLink :exec
DELETE FROM oidc_links
WHERE id = $1;

-- name: DeleteOIDCLinkByUserAndProvider :exec
DELETE FROM oidc_links
WHERE user_id = $1 AND oidc_provider_id = $2;
