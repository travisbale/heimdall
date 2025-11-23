-- name: CreateVerificationToken :one
INSERT INTO verification_tokens (
    user_id,
    token,
    expires_at
) VALUES (
    $1, $2, $3
) ON CONFLICT (user_id) DO UPDATE
SET token = EXCLUDED.token,
    expires_at = EXCLUDED.expires_at,
    created_at = now()
RETURNING *;

-- name: GetVerificationToken :one
SELECT *
FROM verification_tokens
WHERE token = $1;

-- name: DeleteVerificationToken :exec
DELETE FROM verification_tokens
WHERE user_id = $1;

-- name: DeleteExpiredVerificationTokens :exec
DELETE FROM verification_tokens
WHERE expires_at < now();
