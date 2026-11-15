# Database migrations and controlled organization enrollment

**Status: development integration capability, not production qualification.** See ADR 0006 and issue #22.

## Versioned migrations
`scripts/migrations/V001__baseline.sql`, `V002__pilot_audit.sql`, `V003__tenant_admin_invariants.sql` are immutable scripts run in lexical/version order. `scripts/apply-migrations.sh` executes each version in a database transaction with an advisory migration lock and records SHA-256 in `public.schema_migrations`. Applied-file checksum drift is rejected. The script must run using a *separate migration owner* with schema DDL privileges.

For local Docker Compose, `migrate` runs after PostgreSQL becomes healthy and before the API starts. To upgrade an **existing** local volume without deleting data:
```sh
docker compose -f docker/compose.yml run --rm migrate
docker compose -f docker/compose.yml up --build -d
```
This replays no already-applied migrations. It is safe only after reviewing the database and taking a backup; migration checks may stop on invalid pre-existing active organizations. Existing `scripts/postgres-init/` files remain an initial **development-only** seed/bootstrap and are not a substitute for upgrades. **Do not use `down -v` to upgrade.**

For Azure or a separate on-prem PostgreSQL deployment, provide the environment `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` and `MIGRATIONS_DIR` to a controlled, one-shot migration container with network access to the private DB. Execute `sh scripts/apply-migrations.sh` from a PostgreSQL 17+ client image. Terraform does **not** automatically run migrations today; production deployment/rollback is an open task (#18/#19).

`V003` scans for active organizations without any active tenant administrator and aborts if found. Investigate and repair with change control; do not disable the trigger to skip this gate.

## Controlled first administrator
The schema provides `public.bootstrap_organization(id, display_name, first_admin_oidc_sub)`, an atomic operation inserting both the organization and its first active `tenant_admin`. It does *not* generate or validate the IdP user identity itself.

Procedure for an appropriately authorized operator:
1. Verify a trusted issuer's actual `sub` for the intended administrator in the approved IdP, including the issuer/realm/client context. **Do not accept a subject supplied solely by the end user.**
2. Generate a fresh organization UUID outside the request; approve organization name and initial administrator under the organization's onboarding process.
3. Grant `EXECUTE` for this one function to a dedicated privileged provisioning role, never to `PUBLIC` or the runtime API role. Use a distinct restricted login. The local development superuser is NOT a production security example.
4. Execute from an administrative `psql` session (values are example placeholders, not real identities):
```sh
psql -X -v ON_ERROR_STOP=1 \
  -v org_id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' \
  -v org_name='Approved Organization' \
  -v oidc_sub='validated-oidc-subject' <<'SQL'
SELECT public.bootstrap_organization(:'org_id'::uuid, :'org_name', :'oidc_sub');
SQL
```
5. Confirm organization and membership were committed, then configure the IdP to send the matching `organization_id` claim and `tenant_admin` role for that tenant. The pilot API can address only the verified single organization from the token, so managing multiple organizations requires #14.
6. Reconcile/record approval externally. The pilot access audit table does **not** yet seal organization creation evidence.

The function has `REVOKE ALL ... FROM PUBLIC`, but its database *owner* can always execute it. Production requires separate roles/schema ownership and auditing of operator executions. Deny direct membership DML to untrusted users.

## Verification
CI runs `tests/backend/TemporalMark.Postgres.Tests` against a live PostgreSQL 17 Docker container: initial seed preserved, migrations present, no-admin creation/activation forbidden, bad subject inputs rejected, last admin deletion/reassignment forbidden, concurrent admin demotion/deletion serialized. The desktop/mobile and authenticated OIDC UI tests continue to run. Triggers and tests **do not** replace PostgreSQL RLS, cryptographic IdP proof, legally sealed audit or full organization management.

## Signed IdP operator provisioning (#24)
The authenticated operator flow is now handled by a **separate, non-HTTP** .NET CLI, not by manually typing an arbitrary initial-admin subject into PostgreSQL. Consult [operator provisioning](OPERATOR_PROVISIONING.md) and [ADR 0007](../adr/0007-oidc-operator-provisioning.md). The legacy bootstrap function remains for migration-owner only. `V004` defines restricted database grant groups; local Compose creates login credentials only for development. Production must configure its own least-privilege logins through an approved secret management process, not reuse the demo users. IDP claim mapping, real-time revocation and audit sealing are still pending.

`V005` fixes the role boundary in the membership/active-admin constraint triggers. These triggers now execute as their controlled migration owner with qualified names and restricted search paths; they do **not** confer direct `INSERT` or `UPDATE` on the memberships/organizations tables to the runtime/provisioner logins. Trigger-helper direct `EXECUTE` is revoked from `PUBLIC`. Privilege regression tests cover this boundary.

## Scoped approval migrations (#29)

`V006__approved_enrollment.sql` creates a five-minute pending enrollment request bound to UUID, exact name, issuer and distinct `sub` identifiers, with a third `temporalmark_approver_group` that **cannot** call request/complete. The provisioning group loses EXECUTE of the old direct `bootstrap_verified_organization` function. `V007__stable_request_expiration.sql` fixes the clock-sampling precision of the five-minute bound; applied migrations are never edited. The CLI now requires `request` / `approve` / `complete`; see [operator runbook](OPERATOR_PROVISIONING.md) and ADR 0009. The locally seeded `temporalmark_approver` login is a **development-only** fixture, not a production operator IAM design. Test signed roles, account status, privilege denial and one-time completion before any real onboarding.
