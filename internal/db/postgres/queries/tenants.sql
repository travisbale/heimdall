-- name: CreateTenant :one
INSERT INTO tenants (id, created_at, updated_at)
VALUES ($1, NOW(), NOW())
RETURNING *;

-- name: GetTenant :one
SELECT * FROM tenants
WHERE id = $1;

-- name: DeleteTenant :exec
DELETE FROM tenants
WHERE id = $1;
