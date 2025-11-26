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
