-- name: CreateOIDCSession :one
INSERT INTO oidc_sessions (
    state,
    code_verifier,
    oidc_provider_id,
    provider_type,
    redirect_uri,
    tenant_id,
    user_id,
    expires_at,
    operation
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
) RETURNING *;

-- name: GetOIDCSessionByState :one
SELECT * FROM oidc_sessions
WHERE state = $1 AND expires_at > now();

-- name: DeleteOIDCSession :exec
DELETE FROM oidc_sessions
WHERE id = $1;

-- name: DeleteExpiredOIDCSessions :exec
DELETE FROM oidc_sessions
WHERE expires_at <= now();
