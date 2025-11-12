-- Drop OAuth tables (must drop before users due to foreign keys)
DROP TABLE IF EXISTS oauth_sessions;
DROP TABLE IF EXISTS oauth_links;
DROP TABLE IF EXISTS oauth_providers;

-- Drop RLS policies
DROP POLICY IF EXISTS tenant_isolation_policy ON oauth_providers;
DROP POLICY IF EXISTS tenant_isolation_policy ON users;

-- Disable RLS
ALTER TABLE oauth_providers DISABLE ROW LEVEL SECURITY;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;

-- Drop tables
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS verification_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;

-- Drop enum types
DROP TYPE IF EXISTS user_status;
DROP TYPE IF EXISTS tenant_status;
