-- name: InsertLoginAttempt :one
INSERT INTO login_attempts (
    email,
    user_id,
    ip_address,
    locked_until
) VALUES (
    $1, $2, $3, $4
) RETURNING id, email, user_id, ip_address, locked_until, attempted_at, created_at;

-- name: GetRecentFailedAttempts :one
SELECT COUNT(*) as count
FROM login_attempts
WHERE email = $1
  AND attempted_at > $2;

-- name: GetMostRecentLockout :one
-- Gets the most recent non-null locked_until for checking active lockouts
SELECT locked_until
FROM login_attempts
WHERE email = $1
  AND locked_until IS NOT NULL
ORDER BY attempted_at DESC
LIMIT 1;

-- name: DeleteLoginAttempts :exec
-- Delete all login attempts for a user after successful login
-- Failed attempts are no longer relevant once the user has authenticated
DELETE FROM login_attempts
WHERE user_id = $1;
