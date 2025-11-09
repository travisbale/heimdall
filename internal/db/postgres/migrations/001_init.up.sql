-- Create user_status enum type
CREATE TYPE user_status AS ENUM ('unverified', 'active', 'suspended', 'inactive');

-- Create users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status user_status NOT NULL DEFAULT 'unverified',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

-- Create index on tenant_id for efficient querying by tenant
CREATE INDEX idx_users_tenant_id ON users(tenant_id);

-- Create index on email for lookups
CREATE INDEX idx_users_email ON users(email);

-- Create index on status for filtering users by status
CREATE INDEX idx_users_status ON users(status);

-- Create verification_tokens table
CREATE TABLE verification_tokens (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create index on token for fast lookups
CREATE INDEX idx_verification_tokens_token ON verification_tokens(token);

-- Create password_reset_tokens table
CREATE TABLE password_reset_tokens (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create index on token for fast lookups
CREATE INDEX idx_password_reset_tokens_token ON password_reset_tokens(token);

-- Create login_attempts table for tracking failed authentication attempts and account lockout
-- Only failed attempts are recorded; successful logins are tracked via users.last_login_at
CREATE TABLE login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    ip_address TEXT,
    locked_until TIMESTAMPTZ,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create index on email and attempted_at for efficient lockout queries
CREATE INDEX idx_login_attempts_email_time ON login_attempts(email, attempted_at DESC);

-- Create index on user_id for user-specific queries
CREATE INDEX idx_login_attempts_user_id ON login_attempts(user_id);

-- Create index on ip_address for detecting distributed attacks
CREATE INDEX idx_login_attempts_ip ON login_attempts(ip_address);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) - Tenant Isolation
-- ============================================================================
-- Enable RLS to automatically enforce tenant isolation at the database level.
-- This prevents accidental cross-tenant data access even if application code has bugs.

-- Enable RLS on all tenant scoped tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Policy for users table (direct tenant_id)
CREATE POLICY tenant_isolation_policy ON users
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
