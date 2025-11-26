-- name: CreateTrustedDevice :one
INSERT INTO trusted_devices (user_id, tenant_id, token_hash, user_agent, ip_address, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetTrustedDeviceByTokenHash :one
SELECT * FROM trusted_devices
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: UpdateTrustedDeviceLastUsed :exec
UPDATE trusted_devices
SET last_used_at = now(), expires_at = $2, ip_address = $3
WHERE id = $1;

-- name: RevokeAllUserTrustedDevices :exec
UPDATE trusted_devices SET revoked_at = now()
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: DeleteExpiredTrustedDevices :exec
DELETE FROM trusted_devices
WHERE expires_at < now() OR revoked_at < now() - interval '7 days';
