#!/bin/bash
set -e

# Application user must NOT be a superuser for Row-Level Security to work
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER heimdall WITH PASSWORD 'secure_password';
    GRANT CONNECT ON DATABASE heimdall TO heimdall;

    \c heimdall
    GRANT USAGE, CREATE ON SCHEMA public TO heimdall;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO heimdall;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO heimdall;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO heimdall;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO heimdall;
EOSQL

echo "Application user 'heimdall' created successfully"
