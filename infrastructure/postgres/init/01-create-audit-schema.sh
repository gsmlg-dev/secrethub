#!/bin/bash
# Initialize audit schema and extensions for SecretHub
set -e

psql -v "$POSTGRES_USER:$POSTGRES_PASSWORD" -h localhost -U "$POSTGRES_USER" -d "$POSTGRES_DB" << 'EOSQL'
-- Create audit schema
CREATE SCHEMA IF NOT EXISTS audit;

-- Set up extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Grant permissions
GRANT ALL ON SCHEMA audit TO $POSTGRES_USER;
GRANT ALL ON ALL TABLES IN SCHEMA audit TO $POSTGRES_USER;
GRANT ALL ON ALL SEQUENCES IN SCHEMA audit TO $POSTGRES_USER;
EOSQL

echo "✅ Audit schema and extensions initialized"