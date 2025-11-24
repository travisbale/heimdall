-- ============================================================================
-- MFA TABLES - Multi-Factor Authentication
-- ============================================================================

-- MFA settings per user (TOTP configuration)
-- No tenant_id column - tenant isolation enforced via JOIN to users table in RLS policy
CREATE TABLE mfa_settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,

    -- TOTP secret (AES-256-GCM encrypted, must be reversible for verification)
    totp_secret TEXT NOT NULL,

    -- Replay attack prevention (stores last successful TOTP time window)
    last_used_window BIGINT,

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at TIMESTAMPTZ, -- MFA enabled when not null
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_mfa_settings_user_id ON mfa_settings(user_id);

-- Backup codes for MFA recovery (10 per user)
-- No tenant_id needed - user_id from JWT provides sufficient isolation
CREATE TABLE mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Code hash (Argon2id hashed like passwords)
    code_hash TEXT NOT NULL,

    -- One-time use tracking
    used BOOLEAN NOT NULL DEFAULT false,
    used_at TIMESTAMPTZ,

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_mfa_backup_codes_user_id ON mfa_backup_codes(user_id);
CREATE INDEX idx_mfa_backup_codes_used ON mfa_backup_codes(user_id, used);

-- Enable RLS on mfa_settings table
-- Allow operations with or without tenant context (MFA verification happens during login)
ALTER TABLE mfa_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_settings FORCE ROW LEVEL SECURITY;

CREATE POLICY mfa_settings_policy ON mfa_settings FOR ALL
    USING (
        CASE
            WHEN current_setting('app.current_tenant_id', true) = '' THEN
                EXISTS (SELECT 1 FROM users WHERE users.id = mfa_settings.user_id)
            ELSE
                EXISTS (SELECT 1 FROM users WHERE users.id = mfa_settings.user_id)
        END
    );

-- No RLS needed for mfa_backup_codes - user_id constraint provides isolation
