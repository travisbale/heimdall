-- name: CreateUser :one
INSERT INTO users (
    tenant_id,
    email,
    password_hash,
    first_name,
    last_name,
    status
) VALUES (
    $1, $2, $3, $4, $5, $6
) RETURNING *;

-- name: GetUser :one
SELECT *
FROM users
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT *
FROM users
WHERE email = $1 AND status != 'inactive';

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
