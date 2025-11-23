-- name: DeleteAllDirectPermissions :exec
-- Replace all direct permissions for a user (used for bulk updates)
-- Note: This should be called in a transaction with InsertDirectPermissions
DELETE FROM user_permissions
WHERE user_id = $1;

-- name: InsertDirectPermissions :exec
-- Insert multiple direct permissions for a user (called after SetDirectPermissions in transaction)
-- Parameters: user_id, permission_ids array, effects array (strings cast to permission_effect)
INSERT INTO user_permissions (user_id, permission_id, effect)
SELECT @user_id::uuid, unnest(@permission_ids::uuid[]), unnest(@effects::varchar[])::permission_effect;

-- name: GetDirectPermissions :many
-- Get direct permissions assigned to user (not from roles)
SELECT p.id, p.name, p.description, up.effect
FROM permissions p
JOIN user_permissions up ON up.permission_id = p.id
WHERE up.user_id = $1
ORDER BY p.name;
