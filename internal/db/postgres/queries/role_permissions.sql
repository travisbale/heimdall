-- name: GetRolePermissions :many
SELECT p.id, p.name, p.description, rp.created_at as assigned_at
FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
WHERE rp.role_id = $1
ORDER BY p.name;

-- name: DeleteAllRolePermissions :exec
-- Replace all permissions for a role (used for bulk updates)
-- First delete all existing permissions, then insert new ones
-- Note: This should be called in a transaction with InsertRolePermissions
DELETE FROM role_permissions
WHERE role_id = $1;

-- name: InsertRolePermissions :exec
-- Insert multiple permissions for a role (called after SetRolePermissions in transaction)
INSERT INTO role_permissions (role_id, permission_id)
SELECT @role_id::uuid, unnest(@permission_ids::uuid[])
ON CONFLICT (role_id, permission_id) DO NOTHING;
