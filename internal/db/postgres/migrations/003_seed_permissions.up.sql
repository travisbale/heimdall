-- Seed system-wide permissions for Heimdall authentication and authorization service
--
-- The permissions table is global, not tenant-scoped, and every service behind Heimdall
-- registers its scopes here. Heimdall's own scopes are therefore namespaced under
-- "heimdall:" so they cannot collide with a consuming service that has its own notion of
-- users or roles (e.g. "scorecard:tournaments:write").
--
-- These names must match iam.AllScopes exactly; TestListPermissions asserts it.

INSERT INTO permissions (name, description) VALUES
    -- User management
    ('heimdall:user:create', 'Create new user accounts'),
    ('heimdall:user:read', 'View user information and their role/permission assignments'),
    ('heimdall:user:update', 'Update user profile (email, name, status)'),
    ('heimdall:user:delete', 'Delete user accounts'),
    ('heimdall:user:assign', 'Assign roles and permissions to users'),

    -- Role management
    ('heimdall:role:create', 'Create new roles'),
    ('heimdall:role:read', 'View roles and their permissions'),
    ('heimdall:role:update', 'Update roles and their permission assignments'),
    ('heimdall:role:delete', 'Delete roles'),

    -- OIDC provider management
    ('heimdall:oidc:create', 'Create OIDC/SSO provider configurations'),
    ('heimdall:oidc:read', 'View OIDC/SSO provider configurations'),
    ('heimdall:oidc:update', 'Update OIDC/SSO provider settings'),
    ('heimdall:oidc:delete', 'Delete OIDC/SSO provider configurations');
