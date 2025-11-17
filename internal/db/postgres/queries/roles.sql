-- name: CreateRole :one
INSERT INTO roles (tenant_id, name, description)
VALUES ($1, $2, $3)
RETURNING id, tenant_id, name, description, created_at, updated_at;

-- name: GetRoleByID :one
SELECT id, tenant_id, name, description, created_at, updated_at
FROM roles
WHERE id = $1;

-- name: GetRoleByName :one
SELECT id, tenant_id, name, description, created_at, updated_at
FROM roles
WHERE tenant_id = $1 AND name = $2;

-- name: ListRoles :many
SELECT id, tenant_id, name, description, created_at, updated_at
FROM roles
ORDER BY name;

-- name: UpdateRole :one
UPDATE roles
SET name = $2, description = $3, updated_at = NOW()
WHERE id = $1
RETURNING id, tenant_id, name, description, created_at, updated_at;

-- name: DeleteRole :exec
DELETE FROM roles
WHERE id = $1;
