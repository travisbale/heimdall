-- name: CreateUser :one
INSERT INTO users (
    tenant_id,
    email,
    password_hash,
    first_name,
    last_name,
    status
) VALUES (
    current_tenant_id(), $1, $2, $3, $4, $5
) RETURNING *;

-- name: GetUser :one
SELECT *
FROM users
WHERE id = $1;

-- The index on email is partial, so a deactivated row and a live one can hold one address
-- at once — an address is handed to whoever holds the job now. Unordered, this returns
-- whichever row the scan reached first, which is the one the address used to belong to.
-- name: GetUserByEmail :one
SELECT *
FROM users
WHERE email = $1 AND status != 'inactive'
ORDER BY (status = 'active') DESC, created_at DESC
LIMIT 1;

-- name: UpdateUser :one
UPDATE users
SET password_hash = COALESCE(sqlc.narg('password_hash'), password_hash),
    status = COALESCE(sqlc.narg('status'), status),
    updated_at = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: UpdateLastLogin :exec
UPDATE users
SET last_login_at = now()
WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;

-- name: DeleteOldUnverifiedUsers :exec
DELETE FROM users
WHERE status = 'unverified'
  AND created_at < (now() - make_interval(days => $1));
