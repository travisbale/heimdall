-- name: SetUserRoles :exec
-- Replace all roles for a user (used for bulk updates)
-- Note: This should be called in a transaction with InsertUserRoles
DELETE FROM user_roles
WHERE user_id = $1;

-- name: InsertUserRoles :exec
-- Insert multiple roles for a user (called after SetUserRoles in transaction)
-- Parameters: user_id, role_ids array, tenant_id
INSERT INTO user_roles (user_id, role_id, tenant_id)
SELECT @user_id::uuid, unnest(@role_ids::uuid[]), @tenant_id::uuid
ON CONFLICT (user_id, role_id) DO NOTHING;

-- name: GetUserRoles :many
SELECT r.id, r.tenant_id, r.name, r.description, r.created_at, r.updated_at
FROM roles r
JOIN user_roles ur ON ur.role_id = r.id
WHERE ur.user_id = $1
ORDER BY r.name;

-- name: GetRoleUsers :many
-- Get all users with a specific role (for admin UI)
SELECT u.id, u.email
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
WHERE ur.role_id = $1
ORDER BY u.email;
