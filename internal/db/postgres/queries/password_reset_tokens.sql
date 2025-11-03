-- name: CreatePasswordResetToken :one
INSERT INTO password_reset_tokens (
    user_id,
    token,
    expires_at
) VALUES (
    $1, $2, $3
) ON CONFLICT (user_id) DO UPDATE
SET token = EXCLUDED.token,
    expires_at = EXCLUDED.expires_at,
    created_at = now()
RETURNING user_id, token, expires_at, created_at;

-- name: GetPasswordResetToken :one
SELECT user_id, token, expires_at, created_at
FROM password_reset_tokens
WHERE token = $1;

-- name: DeletePasswordResetToken :exec
DELETE FROM password_reset_tokens
WHERE user_id = $1;

-- name: DeleteExpiredPasswordResetTokens :exec
DELETE FROM password_reset_tokens
WHERE expires_at < now();
