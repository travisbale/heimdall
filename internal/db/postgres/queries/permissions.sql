-- name: ListPermissions :many
SELECT id, name, description, created_at
FROM permissions
ORDER BY name;

-- name: GetPermissionByID :one
SELECT id, name, description, created_at
FROM permissions
WHERE id = $1;

-- name: GetUserPermissions :many
-- Get all permissions for a user (from roles + direct permissions)
-- Includes effect from direct permissions for deny logic
SELECT DISTINCT
    p.id,
    p.name,
    p.description,
    COALESCE(up.effect, 'allow') as effect  -- Default to 'allow' for role-based permissions
FROM permissions p
LEFT JOIN role_permissions rp ON rp.permission_id = p.id
LEFT JOIN user_roles ur ON ur.role_id = rp.role_id AND ur.user_id = $1
LEFT JOIN user_permissions up ON up.permission_id = p.id AND up.user_id = $1
WHERE ur.user_id = $1 OR up.user_id = $1
ORDER BY p.name;
