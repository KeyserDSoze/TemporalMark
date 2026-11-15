#!/bin/sh
# DEVELOPMENT ONLY. Password credentials are deliberately not bundled in migrations.
# In production use the platform secret manager and separate restricted logins.
set -eu
: "${DEV_RUNTIME_DB_PASSWORD:?Missing development runtime password}"
: "${DEV_PROVISIONER_DB_PASSWORD:?Missing development provisioner password}"
: "${DEV_APPROVER_DB_PASSWORD:?Missing development approver password}"
psql -X -v ON_ERROR_STOP=1 \
  -v runtime_pw="$DEV_RUNTIME_DB_PASSWORD" \
  -v provisioning_pw="$DEV_PROVISIONER_DB_PASSWORD" \
  -v approver_pw="$DEV_APPROVER_DB_PASSWORD" <<'SQL'
DO $do$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'temporalmark_api') THEN
        CREATE ROLE temporalmark_api LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'temporalmark_provisioner') THEN
        CREATE ROLE temporalmark_provisioner LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'temporalmark_approver') THEN
        CREATE ROLE temporalmark_approver LOGIN;
    END IF;
END
$do$;
ALTER ROLE temporalmark_api LOGIN PASSWORD :'runtime_pw';
ALTER ROLE temporalmark_provisioner LOGIN PASSWORD :'provisioning_pw';
ALTER ROLE temporalmark_approver LOGIN PASSWORD :'approver_pw';
GRANT temporalmark_runtime_group TO temporalmark_api;
GRANT temporalmark_provisioner_group TO temporalmark_provisioner;
GRANT temporalmark_approver_group TO temporalmark_approver;
SQL
