-- Remove all seeded permissions
DELETE FROM permissions WHERE name IN (
    -- User management
    'user:create',
    'user:read',
    'user:update',
    'user:delete',
    'user:assign',

    -- Role management
    'role:create',
    'role:read',
    'role:update',
    'role:delete'
);
