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
-- Tenant isolation enforced via JOIN to users table (users table has RLS)
ALTER TABLE mfa_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_settings FORCE ROW LEVEL SECURITY;

CREATE POLICY mfa_settings_policy ON mfa_settings FOR ALL
    USING (EXISTS (SELECT 1 FROM users WHERE users.id = mfa_settings.user_id));

-- Enable RLS on mfa_backup_codes table
-- Tenant isolation enforced via JOIN to users table (users table has RLS)
ALTER TABLE mfa_backup_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_backup_codes FORCE ROW LEVEL SECURITY;

CREATE POLICY mfa_backup_codes_policy ON mfa_backup_codes FOR ALL
    USING (EXISTS (SELECT 1 FROM users WHERE users.id = mfa_backup_codes.user_id));

-- ============================================================================
-- TRUSTED DEVICES - Skip MFA on Trusted Devices
-- ============================================================================
-- Allows users to mark devices as "trusted" during MFA verification,
-- skipping MFA prompts on subsequent logins from that device.
-- Device trust survives normal logout but is revoked on:
-- - Sign out everywhere
-- - Password change
-- - Token reuse detection (potential theft)

CREATE TABLE trusted_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- SHA-256 hash of device token (never store raw tokens)
    token_hash TEXT NOT NULL,

    -- Metadata for user visibility (device name derived from user_agent when needed)
    user_agent TEXT NOT NULL,
    ip_address TEXT NOT NULL,

    -- Lifecycle timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT trusted_devices_token_hash_unique UNIQUE (token_hash),
    CONSTRAINT trusted_devices_valid_expiry CHECK (expires_at > created_at)
);

-- Index for token lookup during login (most common operation)
CREATE INDEX idx_trusted_devices_token_hash ON trusted_devices(token_hash)
    WHERE revoked_at IS NULL;

-- Index for listing user's devices and bulk revocation
CREATE INDEX idx_trusted_devices_user_id ON trusted_devices(user_id)
    WHERE revoked_at IS NULL;

-- Index for cleanup job
CREATE INDEX idx_trusted_devices_expires_at ON trusted_devices(expires_at);

-- Enable RLS with denormalized tenant_id for simpler policy
ALTER TABLE trusted_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE trusted_devices FORCE ROW LEVEL SECURITY;

-- Strict tenant isolation
CREATE POLICY tenant_isolation_policy ON trusted_devices FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);
