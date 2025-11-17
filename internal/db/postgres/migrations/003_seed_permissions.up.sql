-- Seed system-wide permissions for Heimdall authentication and authorization service

INSERT INTO permissions (name, description) VALUES
    -- User management
    ('user:create', 'Create new user accounts'),
    ('user:read', 'View user information and their role/permission assignments'),
    ('user:update', 'Update user profile (email, name, status)'),
    ('user:delete', 'Delete user accounts'),
    ('user:assign', 'Assign roles and permissions to users'),

    -- Role management
    ('role:create', 'Create new roles'),
    ('role:read', 'View roles and their permissions'),
    ('role:update', 'Update roles and their permission assignments'),
    ('role:delete', 'Delete roles'),

    -- OIDC provider management
    ('oidc:create', 'Create OIDC/SSO provider configurations'),
    ('oidc:read', 'View OIDC/SSO provider configurations'),
    ('oidc:update', 'Update OIDC/SSO provider settings'),
    ('oidc:delete', 'Delete OIDC/SSO provider configurations');
