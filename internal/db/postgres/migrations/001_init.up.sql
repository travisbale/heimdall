-- Create user_status enum type
CREATE TYPE user_status AS ENUM ('unverified', 'active', 'suspended', 'inactive');

-- Create oidc_provider_type enum type
CREATE TYPE oidc_provider_type AS ENUM ('google', 'microsoft', 'github', 'okta');

-- Create oidc_registration_method enum type
CREATE TYPE oidc_registration_method AS ENUM ('manual', 'dynamic');

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

-- ============================================================================
-- OIDC TABLES - Single Sign-On Support
-- ============================================================================

-- OIDC provider configurations
-- Stores per-tenant OIDC provider settings (dynamically registered)
CREATE TABLE oidc_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,

    -- User-defined name for display (e.g., "Azure AD - Production", "Google Workspace")
    provider_name TEXT NOT NULL,

    -- OIDC issuer URL for discovery (e.g., https://accounts.google.com)
    issuer_url TEXT NOT NULL,

    -- OAuth client credentials (populated by dynamic registration)
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL, -- TODO: Encrypt at rest in production

    -- Configuration
    scopes TEXT[] DEFAULT ARRAY['openid', 'email', 'profile'],
    enabled BOOLEAN NOT NULL DEFAULT true,

    -- Enterprise SSO configuration
    allowed_domains TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[], -- Email domains allowed (e.g., ['acmecorp.com'])
    auto_create_users BOOLEAN NOT NULL DEFAULT false, -- Automatically create users on first SSO login
    require_email_verification BOOLEAN NOT NULL DEFAULT false, -- Require email verification for auto-created users

    -- Dynamic Client Registration (RFC 7591) - optional fields
    registration_access_token TEXT, -- Token to manage the dynamic registration
    registration_client_uri TEXT, -- Endpoint to update/delete the registration
    client_id_issued_at TIMESTAMPTZ, -- When credentials were issued
    client_secret_expires_at TIMESTAMPTZ, -- When secret expires (provider-dependent)

    -- Registration method tracking
    registration_method oidc_registration_method NOT NULL DEFAULT 'manual',

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- One issuer URL per tenant (prevent duplicate configurations)
    UNIQUE(tenant_id, issuer_url)
);

-- Index for looking up enabled providers by tenant
CREATE INDEX idx_oidc_providers_tenant_enabled ON oidc_providers(tenant_id, enabled);

-- Index for domain-based tenant discovery (GIN index for array contains)
CREATE INDEX idx_oidc_providers_domains ON oidc_providers USING GIN (allowed_domains);

-- Row Level Security for multi-tenancy
ALTER TABLE oidc_providers ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON oidc_providers
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- OIDC provider linkages to users
-- Tracks which OIDC providers each user has connected
CREATE TABLE oidc_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Reference to the specific OIDC provider configuration
    oidc_provider_id UUID NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,

    -- Provider's unique identifier for this user (e.g., Google's 'sub' claim)
    provider_user_id TEXT NOT NULL,
    provider_email TEXT NOT NULL,

    -- Store additional provider data (name, picture, etc.)
    provider_metadata JSONB,

    -- Timestamps
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,

    -- A user can only link one account per provider configuration
    UNIQUE(user_id, oidc_provider_id),

    -- A provider user ID can only be linked to one user per provider config (prevent account takeover)
    UNIQUE(oidc_provider_id, provider_user_id)
);

-- Index for looking up user by provider credentials
CREATE INDEX idx_oidc_links_provider_lookup ON oidc_links(oidc_provider_id, provider_user_id);

-- Index for looking up all linked providers for a user
CREATE INDEX idx_oidc_links_user_id ON oidc_links(user_id);

-- OIDC flow sessions
-- Stores state and PKCE verifiers for OIDC flows (CSRF and replay protection)
CREATE TABLE oidc_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- CSRF protection
    state TEXT NOT NULL UNIQUE,

    -- PKCE support (Proof Key for Code Exchange)
    code_verifier TEXT,

    -- Flow metadata
    -- For corporate SSO: oidc_provider_id references oidc_providers table
    -- For individual OAuth: oidc_provider_id is NULL, use system provider based on provider_type
    oidc_provider_id UUID REFERENCES oidc_providers(id) ON DELETE CASCADE,
    provider_type oidc_provider_type, -- Only for system-wide providers (individual OAuth)
    redirect_uri TEXT,
    tenant_id UUID,
    user_id UUID, -- For link operations, stores the authenticated user

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,

    -- Optional: track if this is a link operation vs. login
    operation TEXT DEFAULT 'login' -- 'login' or 'link'
);

-- Index for state lookup (used on callback)
CREATE INDEX idx_oidc_sessions_state ON oidc_sessions(state);

-- Auto-cleanup expired sessions
CREATE INDEX idx_oidc_sessions_expires_at ON oidc_sessions(expires_at);
