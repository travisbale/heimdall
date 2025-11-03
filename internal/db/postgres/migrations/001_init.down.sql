-- Drop RLS policies
DROP POLICY IF EXISTS tenant_isolation_policy ON users;

-- Disable RLS
ALTER TABLE users DISABLE ROW LEVEL SECURITY;

-- Drop tables
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS verification_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;

-- Drop enum types
DROP TYPE IF EXISTS user_status;
DROP TYPE IF EXISTS tenant_status;
