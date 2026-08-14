-- A window is reused in place once it has expired, so a key holds one row for its
-- lifetime and the count resets without a delete.
-- name: IncrementRateLimit :one
INSERT INTO rate_limits (key, count, expires_at)
VALUES (sqlc.arg('key'), 1, now() + sqlc.arg('window')::interval)
ON CONFLICT (key) DO UPDATE
SET count      = CASE WHEN rate_limits.expires_at <= now() THEN 1 ELSE rate_limits.count + 1 END,
    expires_at = CASE WHEN rate_limits.expires_at <= now() THEN now() + sqlc.arg('window')::interval ELSE rate_limits.expires_at END
RETURNING count, expires_at;

-- name: PeekRateLimit :one
SELECT (CASE WHEN expires_at <= now() THEN 0 ELSE count END)::bigint AS count, expires_at
FROM rate_limits
WHERE key = sqlc.arg('key');

-- name: ResetRateLimit :exec
DELETE FROM rate_limits WHERE key = sqlc.arg('key');

-- Swept on a schedule rather than per request: an expired row is harmless until reused.
-- name: DeleteExpiredRateLimits :exec
DELETE FROM rate_limits WHERE expires_at <= now();
