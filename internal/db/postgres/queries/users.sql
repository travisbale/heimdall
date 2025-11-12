-- name: CreateUser :one
INSERT INTO users (
    tenant_id,
    email,
    password_hash,
    status
) VALUES (
    $1, $2, $3, $4
) RETURNING id, tenant_id, email, password_hash, status, created_at, updated_at, last_login_at;

-- name: GetUser :one
SELECT id, tenant_id, email, password_hash, status, created_at, updated_at, last_login_at
FROM users
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT id, tenant_id, email, password_hash, status, created_at, updated_at, last_login_at
FROM users
WHERE email = $1;

-- name: UpdateUser :one
UPDATE users
SET email = $2,
    status = $3,
    updated_at = now()
WHERE id = $1
RETURNING id, tenant_id, email, password_hash, status, created_at, updated_at, last_login_at;

-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = $2,
    updated_at = now()
WHERE id = $1;

-- name: UpdateLastLogin :exec
UPDATE users
SET last_login_at = now()
WHERE id = $1;

-- name: UpdateUserStatus :one
UPDATE users
SET status = $2,
    updated_at = now()
WHERE id = $1
RETURNING id, tenant_id, email, password_hash, status, created_at, updated_at, last_login_at;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;

-- name: DeleteOldUnverifiedUsers :exec
DELETE FROM users
WHERE status = 'unverified'
  AND created_at < (now() - make_interval(days => $1));
