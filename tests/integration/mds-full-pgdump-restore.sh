#!/usr/bin/env bash
# CI ONLY — full PostgreSQL 17 logical pg_dump/pg_restore into a NEW
# disposable database, then xUnit verifies the existing ADR 0034 two-domain
# signed test witness against the old restored and newer live snapshots.
# NO production independent high-water custody; always UNAPPROVED.
# Never use --no-acl: restored PUBLIC/function and role permissions must
# match the original. This is not pg_basebackup, PITR or certified DR.
set -euo pipefail
umask 077
export LC_ALL=C

: "${TEMPORALMARK_TEST_DB:?CI-only primary database owner connection required}"
command -v dotnet >/dev/null
command -v docker >/dev/null
command -v openssl >/dev/null
command -v sha256sum >/dev/null

dc_pg() {
  docker compose -f docker/compose.yml exec -T postgres "$@"
}

# A SECOND PostgreSQL 17 SERVER, separate data volume and distinct
# read-only witness login. This is opt-in CI only and is NOT WORM, HSM
# or approved independent administrative custody.
docker compose -f docker/compose.yml --profile witness-ci up -d --wait witness-postgres
docker compose -f docker/compose.yml --profile witness-ci exec -T \
  witness-postgres pg_isready -U temporalmark_witness_owner -d temporalmark_witness
docker compose -f docker/compose.yml --profile witness-ci exec -T \
  witness-postgres psql -X -At -v ON_ERROR_STOP=1 \
    -U temporalmark_witness_owner -d temporalmark_witness \
    -c "SELECT count(*) FROM public.unapproved_witness_checkpoints" >/dev/null

hash64() {
  printf '%s' "$1" | sha256sum | cut -d ' ' -f 1 | tr 'abcdef' 'ABCDEF'
}

nonce="$(openssl rand -hex 12)"
policy="$(hash64 "TemporalMark full logical restore test policy ${nonce}")"
issuer="$(hash64 "TemporalMark full logical restore test issuer ${nonce}")"
old_digest="$(hash64 "TemporalMark full logical restore test old evidence ${nonce}")"
new_digest="$(hash64 "TemporalMark full logical restore test latest evidence ${nonce}")"
restore_db="temporalmark_restore_${nonce}"
work_dir="$(mktemp -d)"
database_created=0

cleanup() {
  if [ "$database_created" -eq 1 ]; then
    dc_pg dropdb -U temporalmark --force "$restore_db" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Owner-only staging of one synthetic UNAPPROVED checkpoint. The only
# modifications to the primary are two ordinary disposable test candidate
# versions; the V015/V016 SQL issuance freeze and migrations are unchanged.
old_result="$(
  dc_pg psql -X -At -v ON_ERROR_STOP=1 -U temporalmark -d temporalmark \
    -v scope="$policy" -v issuer="$issuer" -v evidence="$old_digest" <<'SQL'
SELECT public.record_unapproved_mds_checkpoint_candidate(
  'MDS_BLOB', :'issuer', 3, :'evidence', :'scope', 3600,
  'CAB-TEST-FULL-LOGICAL-RESTORE');
SQL
)"
test "$old_result" = "UNAPPROVED"

# A WHOLE LOGICAL DATABASE ARCHIVE: not a filtered COPY of one table.
# Keep archive bytes runner-private and never upload them as CI artifacts.
dc_pg pg_dump -U temporalmark -d temporalmark --format=custom \
  > "$work_dir/old-database.dump"
test -s "$work_dir/old-database.dump"

new_result="$(
  dc_pg psql -X -At -v ON_ERROR_STOP=1 -U temporalmark -d temporalmark \
    -v scope="$policy" -v issuer="$issuer" -v evidence="$new_digest" <<'SQL'
SELECT public.record_unapproved_mds_checkpoint_candidate(
  'MDS_BLOB', :'issuer', 4, :'evidence', :'scope', 3600,
  'CAB-TEST-FULL-LOGICAL-RESTORE');
SQL
)"
test "$new_result" = "UNAPPROVED"

# Restore into a NEW, unique and disposable database on the SAME 17.x
# PostgreSQL test server. Do not overwrite original, use template0, and
# abort the entire restore transaction if ANY object/ACL operation fails.
dc_pg createdb -U temporalmark --template=template0 "$restore_db"
database_created=1
dc_pg pg_restore -U temporalmark -d "$restore_db" \
  --single-transaction --exit-on-error --no-owner \
  < "$work_dir/old-database.dump"

# Explicitly assert immutable migration history, independent restored
# old serial, and still-advanced live serial before the .NET signatures.
restored_migrations="$(
  dc_pg psql -X -At -v ON_ERROR_STOP=1 -U temporalmark -d "$restore_db" \
    -c 'SELECT count(*) FROM public.schema_migrations'
)"
test "$restored_migrations" = "17"

restored_serial="$(
  dc_pg psql -X -At -v ON_ERROR_STOP=1 -U temporalmark -d "$restore_db" \
    -v scope="$policy" -v issuer="$issuer" <<'SQL'
SELECT candidate_serial
FROM public.mds_unapproved_candidate_checkpoints
WHERE candidate_kind='MDS_BLOB'
  AND issuer_key_sha256=:'issuer'
  AND source_policy_sha256=:'scope';
SQL
)"
live_serial="$(
  dc_pg psql -X -At -v ON_ERROR_STOP=1 -U temporalmark -d temporalmark \
    -v scope="$policy" -v issuer="$issuer" <<'SQL'
SELECT candidate_serial
FROM public.mds_unapproved_candidate_checkpoints
WHERE candidate_kind='MDS_BLOB'
  AND issuer_key_sha256=:'issuer'
  AND source_policy_sha256=:'scope';
SQL
)"
test "$restored_serial" = "3"
test "$live_serial" = "4"

# The restored SQL grants are part of the threat boundary. Restoring with
# --no-acl could silently enable PUBLIC EXECUTE of checkpoint functions.
restored_unprivileged_execute="$(
  dc_pg psql -X -At -v ON_ERROR_STOP=1 -U temporalmark -d "$restore_db" <<'SQL'
SELECT has_function_privilege(
  'temporalmark_approver_group',
  'public.record_unapproved_mds_checkpoint_candidate(text,text,bigint,text,text,integer,text)',
  'EXECUTE');
SQL
)"
test "$restored_unprivileged_execute" = "f"

# The .NET xUnit test generates two SEPARATE disposable RSA-PSS signing
# keys in its own process and retains the latest test seal hash outside BOTH
# databases. A real HSM/immutable monotonic signing authority is #64.
TEMPORALMARK_RUN_FULL_PGDUMP_RESTORE_TEST=1 \
TEMPORALMARK_RESTORE_TEST_DB="Host=127.0.0.1;Port=5432;Database=${restore_db};Username=temporalmark;Password=local-dev-only" \
TEMPORALMARK_RESTORE_POLICY_SHA256="$policy" \
TEMPORALMARK_RESTORE_ISSUER_SHA256="$issuer" \
TEMPORALMARK_RESTORE_OLD_EVIDENCE_SHA256="$old_digest" \
TEMPORALMARK_RESTORE_NEW_EVIDENCE_SHA256="$new_digest" \
TEMPORALMARK_RUN_ISOLATED_WITNESS_TEST=1 \
TEMPORALMARK_WITNESS_OWNER_TEST_DB="Host=127.0.0.1;Port=5433;Database=temporalmark_witness;Username=temporalmark_witness_owner;Password=local-witness-owner-only" \
TEMPORALMARK_WITNESS_WRITER_TEST_DB="Host=127.0.0.1;Port=5433;Database=temporalmark_witness;Username=temporalmark_witness_writer;Password=local-witness-writer-only" \
TEMPORALMARK_WITNESS_TEST_DB="Host=127.0.0.1;Port=5433;Database=temporalmark_witness;Username=temporalmark_witness_reader;Password=local-witness-reader-only" \
dotnet test tests/backend/TemporalMark.Postgres.Tests/TemporalMark.Postgres.Tests.csproj \
  --configuration Release \
  --filter 'FullyQualifiedName~MdsFullPgDumpRestorePostgresTests'

printf '%s\n' "PASS: full PostgreSQL logical pg_dump/pg_restore rollback is detected only with latest TEST seal pin; all outcomes UNAPPROVED."
