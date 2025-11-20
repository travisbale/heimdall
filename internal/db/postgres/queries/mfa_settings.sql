-- name: CreateMFASettings :one
INSERT INTO mfa_settings (
    user_id,
    tenant_id,
    totp_secret
) VALUES ($1, $2, $3)
RETURNING *;

-- name: GetMFASettingsByUserID :one
SELECT * FROM mfa_settings WHERE user_id = $1;

-- name: UpdateMFASettings :exec
UPDATE mfa_settings
SET
    last_used_window = $2,
    verified_at = $3,
    last_used_at = $4
WHERE user_id = $1;

-- name: DeleteMFASettings :exec
DELETE FROM mfa_settings WHERE user_id = $1;
