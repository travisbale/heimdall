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

-- Enable RLS (JOIN-based pattern like mfa_settings)
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;

-- SELECT: Allow with or without tenant context
-- Without context (pre-auth): token validation during refresh
-- With context (post-auth): list user's sessions
CREATE POLICY refresh_tokens_select_policy ON refresh_tokens FOR SELECT
    USING (
        CASE
            WHEN current_setting('app.current_tenant_id', true) = '' THEN true
            ELSE EXISTS (SELECT 1 FROM users WHERE users.id = refresh_tokens.user_id)
        END
    );

-- INSERT: Allow with or without tenant context (login creates tokens)
CREATE POLICY refresh_tokens_insert_policy ON refresh_tokens FOR INSERT
    WITH CHECK (user_id IS NOT NULL AND tenant_id IS NOT NULL);

-- UPDATE: Allow with or without tenant context (refresh updates last_used_at, logout sets revoked_at)
CREATE POLICY refresh_tokens_update_policy ON refresh_tokens FOR UPDATE
    USING (
        CASE
            WHEN current_setting('app.current_tenant_id', true) = '' THEN true
            ELSE EXISTS (SELECT 1 FROM users WHERE users.id = refresh_tokens.user_id)
        END
    );

-- DELETE: Cleanup job runs without tenant context
CREATE POLICY refresh_tokens_delete_policy ON refresh_tokens FOR DELETE
    USING (true);
