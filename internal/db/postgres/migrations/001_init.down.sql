-- Drop OIDC tables (must drop before users due to foreign keys)
DROP TABLE IF EXISTS oidc_sessions;
DROP TABLE IF EXISTS oidc_links;
DROP TABLE IF EXISTS oidc_providers;

-- Drop other tables
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS verification_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;

-- Drop enum types
DROP TYPE IF EXISTS oidc_registration_method;
DROP TYPE IF EXISTS oidc_provider_type;
DROP TYPE IF EXISTS user_status;
