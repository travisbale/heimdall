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

-- tenants carries no RLS, so this is readable with no tenant context — which is what lets
-- the cleanup find the tenants whose expired rows its policies would otherwise hide.
-- name: ListTenantIDs :many
SELECT id FROM tenants ORDER BY id;
