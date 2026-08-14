-- Rate limit counters, shared by every instance. An in-memory store gives each container
-- its own count, so the effective limit multiplies by however many are running.
CREATE TABLE rate_limits (
    key TEXT PRIMARY KEY,
    count BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- Expired rows are reused in place, so this only serves the sweep.
CREATE INDEX idx_rate_limits_expires_at ON rate_limits(expires_at);
