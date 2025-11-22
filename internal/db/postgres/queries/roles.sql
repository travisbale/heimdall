-- name: CreateRole :one
INSERT INTO roles (tenant_id, name, description, mfa_required)
VALUES (sqlc.arg('tenant_id'), sqlc.arg('name'), sqlc.arg('description'), sqlc.arg('mfa_required'))
RETURNING id, name, description, mfa_required;

-- name: GetRoleByID :one
SELECT id, name, description, mfa_required
FROM roles
WHERE id = $1;

-- name: ListRoles :many
SELECT id, name, description, mfa_required
FROM roles
ORDER BY name;

-- name: UpdateRole :one
UPDATE roles
SET name = COALESCE(sqlc.narg('name'), name),
    description = COALESCE(sqlc.narg('description'), description),
    mfa_required = COALESCE(sqlc.narg('mfa_required'), mfa_required),
    updated_at = NOW()
WHERE id = sqlc.arg('id')
RETURNING id, name, description, mfa_required;

-- name: DeleteRole :exec
DELETE FROM roles
WHERE id = $1;
