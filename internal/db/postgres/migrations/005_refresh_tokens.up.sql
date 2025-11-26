-- ============================================================================
-- REFRESH TOKENS - Session Management
-- ============================================================================
-- Stores refresh token metadata for session management features:
-- - List active sessions (devices/browsers)
-- - Revoke specific sessions
-- - "Sign out everywhere" functionality

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- SHA-256 hash of the JWT refresh token (never store raw tokens)
    token_hash TEXT NOT NULL UNIQUE,

    -- Token family for rotation tracking (all tokens from same login share this ID)
    family_id UUID NOT NULL,

    -- Session metadata for display and security
    user_agent TEXT NOT NULL,
    ip_address TEXT NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT refresh_tokens_valid_expiry CHECK (expires_at > created_at)
);

-- Index for user's sessions list
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- Index for token validation on refresh
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);

-- Index for cleanup job
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Index for family revocation (token rotation reuse detection)
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens(family_id);

-- Enable RLS
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;

-- Strict tenant isolation - all operations require tenant context
CREATE POLICY tenant_isolation_policy ON refresh_tokens FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);
