#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE heimdall;
    GRANT ALL PRIVILEGES ON DATABASE heimdall TO $POSTGRES_USER;
EOSQL

echo "Database created successfully"
