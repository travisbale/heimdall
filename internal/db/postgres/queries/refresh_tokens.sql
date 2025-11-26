-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, family_id, user_agent, ip_address, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: ListUserRefreshTokens :many
SELECT * FROM refresh_tokens
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
ORDER BY last_used_at DESC;

-- name: UpdateRefreshTokenLastUsed :exec
UPDATE refresh_tokens SET last_used_at = now() WHERE id = $1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeRefreshTokenByHash :exec
UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL;

-- name: RevokeAllUserRefreshTokens :exec
UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at < now() OR revoked_at < now() - interval '7 days';

-- name: GetRefreshTokenByHashIncludingRevoked :one
-- Used for token rotation reuse detection - returns token even if revoked
SELECT * FROM refresh_tokens
WHERE token_hash = $1 AND expires_at > now();

-- name: RevokeRefreshTokenFamily :exec
-- Revokes all tokens in a family (used when token reuse is detected)
UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL;
