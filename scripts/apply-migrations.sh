#!/bin/sh
# Transactional, checksummed migrations for PostgreSQL 17+.
# Requires psql, sha256sum, PostgreSQL migration-owner credentials (PGHOST, PGUSER,
# PGPASSWORD, PGDATABASE), and exclusive DB-object privileges.
set -eu
dir="${MIGRATIONS_DIR:-/migrations}"
if [ ! -d "$dir" ]; then
  echo "Missing migration directory: $dir" >&2
  exit 1
fi
set -- "$dir"/V[0-9][0-9][0-9]__*.sql
if [ ! -f "$1" ]; then
  echo "No versioned migrations found in $dir" >&2
  exit 1
fi
for file do
  base="${file##*/}"
  version="${base%%__*}"
  digest="$(sha256sum "$file" | cut -d ' ' -f 1)"
  echo "Checking $base"
  # All checks and the migration run in one DB transaction, protected from
  # concurrent migration runners. Existing file checksums cannot drift.
  psql -X -v ON_ERROR_STOP=1 -v version="$version" -v digest="$digest" <<SQL
BEGIN;
SELECT pg_advisory_xact_lock(19171, 302);
CREATE TABLE IF NOT EXISTS public.schema_migrations (
    version text PRIMARY KEY,
    sha256 char(64) NOT NULL,
    applied_utc timestamptz NOT NULL DEFAULT now()
);
SELECT EXISTS (
    SELECT 1 FROM public.schema_migrations
     WHERE version = :'version'
) AS already_applied,
EXISTS (
    SELECT 1 FROM public.schema_migrations
     WHERE version = :'version' AND sha256 <> :'digest'
) AS checksum_drift
\gset
\if :checksum_drift
    -- Intentional failure makes checksum edits fail closed.
    SELECT 1 / 0 AS unchanged_migrations_are_required;
\endif
\if :already_applied
    \echo '$version already applied with matching checksum'
\else
    \i $file
    INSERT INTO public.schema_migrations(version, sha256)
        VALUES (:'version', :'digest');
\endif
COMMIT;
SQL
done
