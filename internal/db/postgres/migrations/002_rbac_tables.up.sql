-- Permission effect types (allow/deny)
CREATE TYPE permission_effect AS ENUM ('allow', 'deny');

-- System-wide permissions (no tenant_id - shared across all tenants)
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,  -- e.g., "employee:create"
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT permissions_name_format_check CHECK (name ~ '^[a-z0-9_]+:[a-z0-9_]+$')
);

-- Tenant-specific roles (user-manageable)
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    mfa_required BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

-- Enable RLS on roles table
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner (critical for proper tenant isolation)
ALTER TABLE roles FORCE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation (strict - no cross-tenant access)
CREATE POLICY tenant_isolation_policy ON roles
    FOR ALL
    TO PUBLIC
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- Role permissions (which permissions does this role grant?)
CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

-- Enable RLS on role_permissions table
ALTER TABLE role_permissions ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner
ALTER TABLE role_permissions FORCE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation using join to roles table
-- NOTE: The EXISTS subquery sees an RLS-filtered view of roles table
CREATE POLICY tenant_isolation_policy ON role_permissions
    FOR ALL
    TO PUBLIC
    USING (EXISTS (
        SELECT 1 FROM roles WHERE roles.id = role_permissions.role_id
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM roles WHERE roles.id = role_permissions.role_id
    ));

-- User roles (which roles does this user have?)
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Enable RLS on user_roles table
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner
ALTER TABLE user_roles FORCE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation using join to users and roles tables
-- NOTE: The EXISTS subqueries will see RLS-filtered views of users/roles tables,
-- which automatically enforces tenant isolation. We just need to verify the records exist.
CREATE POLICY tenant_isolation_policy ON user_roles
    FOR ALL
    TO PUBLIC
    USING (EXISTS (
        SELECT 1 FROM users WHERE users.id = user_roles.user_id
    ) AND EXISTS (
        SELECT 1 FROM roles WHERE roles.id = user_roles.role_id
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM users WHERE users.id = user_roles.user_id
    ) AND EXISTS (
        SELECT 1 FROM roles WHERE roles.id = user_roles.role_id
    ));

-- Direct user permissions (allow/deny overrides)
CREATE TABLE user_permissions (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    effect permission_effect NOT NULL,
    PRIMARY KEY (user_id, permission_id)
);

-- Enable RLS on user_permissions table
ALTER TABLE user_permissions ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner
ALTER TABLE user_permissions FORCE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation using join to users table
-- NOTE: The EXISTS subquery sees an RLS-filtered view of users table
CREATE POLICY tenant_isolation_policy ON user_permissions
    FOR ALL
    TO PUBLIC
    USING (EXISTS (
        SELECT 1 FROM users WHERE users.id = user_permissions.user_id
    ))
    WITH CHECK (EXISTS (
        SELECT 1 FROM users WHERE users.id = user_permissions.user_id
    ));

-- Indexes for performance
CREATE INDEX idx_roles_tenant_id ON roles(tenant_id);
CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_user_permissions_user_id ON user_permissions(user_id);
CREATE INDEX idx_user_permissions_permission_id ON user_permissions(permission_id);
