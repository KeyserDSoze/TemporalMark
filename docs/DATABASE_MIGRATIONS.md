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

## V008 — Approval provenance (#33)

New immutable migration `V008__approval_assurance_provenance.sql` adds bounded authentication classification, ACR, UTC authentication time and policy ID to approval requests, linked to existing organization provisioning events. It revokes restricted approver EXECUTE on the seven-argument legacy approval function. The new ten-argument function accepts signed IdP ACR claims with recent authentication time or explicitly classified **non-MFA** localhost demo evidence only. Historical approvals are labelled `LEGACY_UNVERIFIED`; previously consumed records remain, while pending legacy approvals cannot newly complete. These rows are normal PostgreSQL pilot audit data, NOT legally sealed/WORM evidence. See [ADR 0012](../adr/0012-approval-assurance-provenance.md).

## V009 — Original reviewer scope (#36)

`V009__reviewer_original_scope_read.sql` creates a SECURITY DEFINER read-only routine, EXECUTE-granted only to the restricted approver role. It returns one still-pending unexpired original organization request, matching pinned issuer and a third reviewer subject. No table SELECT, global enumeration or sensitive proof hashes. A verified reviewer receives a domain-separated SHA-256 bound to exact scope and expiration, and the CLI requires explicit digest confirmation before existing SQL approval. **The digest is not a legally signed decision**, and an authorized approver SQL login remains a sensitive trust boundary. ADR 0014; parent #35 is open.

## V010 — Terminal rejection and common reviewer token-proof ledger (#37)

`V010__terminal_enrollment_rejection.sql` adds bounded, nullable terminal REJECTED metadata to the original `organization_enrollment_requests` table and enforces mutually exclusive approval/rejection with SQL CHECK constraints. Only the approver SQL role may EXECUTE `reject_enrollment(uuid,text,text,text,text,text,char(64),char(64),text)`; the client must re-review exact original issuer/name/operator/admin and confirm the SHA-256. Reason codes are fixed; no freeform personal data or access-token bytes are stored. The previously approved/non-approved records are unchanged. The existing reviewer-read routine is redefined in V010 to hide rejected requests, and a new owner-only token-proof ledger is populated with existing approved fingerprints then maintained by an AFTER UPDATE trigger. Each reviewer JWT SHA-256 may authorize **one approval or rejection**, not both or multiple, and competing decisions serialize on the pending row. Ordinary SQL audit is **NOT WORM/qualified evidence**; the SQL role cannot cryptographically prove human possession or signed intent. See [ADR 0015](../adr/0015-terminal-rejection-and-token-proof-replay.md).

## V011 — Strict nonnull rejection invariants (#37)

PostgreSQL `CHECK` constraints accept a row when the expression is `UNKNOWN` (NULL), not only when it is TRUE. In V010 the optional fields are checked with regular expressions and an allowlist only *after* `rejected_utc` becomes non-null. V011 explicitly requires `rejection_proof_sha256 IS NOT NULL`, `rejection_review_sha256 IS NOT NULL`, `rejection_reason_code IS NOT NULL` and `rejected_by_subject IS NOT NULL` on every terminal rejection; a negative owner-level SQL integration test proves missing digest/reason rows are refused. V010 remains immutable and V011 is applied through the checksum-enforcing migrator. No production WORM/compliance claim follows.

## V012 — one-time, unsigned reviewer challenge (#39)

New `V012__bound_reviewer_decision_challenge.sql`: append-only-by-trigger owner table with a unique request ID, random 48-byte nonce, action, fixed reason, issuer/reviewer, original review SHA and bounded TTL. SECURITY DEFINER issues only for a still-pending exact original scope; PostgreSQL independently recomputes the UTF-8 length-prefixed digest and verifies expiry, using built-in SHA-256 (no pgcrypto extension). Only approver group has EXECUTE on issuing function; approver/runtime/provisioner have **no table SELECT/DML** or helper EXECUTE. **No consumer exists: a nonce cannot authorize a decision.** Migration count=12; V001–V011 immutable. ADR 0016, #38.

## V013 — owner-pinned WebAuthn RP registration intent (#45)

`V013__reviewer_registration_intent.sql` adds a **schema-owner-pinned** exact HTTPS issuer/RP/origin policy and a short-lived, append-only **unconsumable registration intent**, protected by an independent `temporalmark_credential_registrar_group NOLOGIN` role. No members/logins or policy rows are created by the migration. EXECUTE on `issue_reviewer_registration_intent` is available only to that new group; it cannot SELECT/INSERT/UPDATE/DELETE policy or intent rows, while existing approver, provisioner and runtime groups have no EXECUTE. The migration owner is still privileged, so ordinary triggers are **not WORM**. The nonce is three v4 UUIDs (48 bytes; roughly 366 effective random bits), expiry <=2 minutes, at most one intent ever per pinned issuer/reviewer/RP. Issuer and subject parameters are **not IdP-authenticated at the SQL level**. There are **no credential IDs, COSE public keys, attestation, ACTIVE records, consumption, WebAuthn verification endpoints or organization approvals**. Do not grant the NOLOGIN role membership, install a registrar login, or assume registration works until reviewed current-role/strong-MFA identity and FIDO2 verification under #44. An expired intent intentionally cannot be reissued automatically; reviewed recovery needs another ADR/migration. CI now expects **13** checksummed migrations; never rewrite V013 after deployment. See [ADR 0021](../adr/0021-registrar-only-unconsumable-credential-intent.md) and [runbook](WEBAUTHN_REGISTRAR_INTENT.md), and keep #38/#44 open.


## V014 — strict registration RP DNS name (#45)

After V013, immutable `V014__registrar_rp_dns_integrity.sql` adds a forward-only CHECK constraint and helper to reject raw IPv4 RP identifiers, numeric-only final DNS labels and labels over 63 characters. Do **not** modify V013/checksums. Both the GitHub CI migration count and persistent-seed database test now expect **14**. Unsafe existing owner-pinned RP rows cause migration failure for change-controlled correction, rather than silent relaxation. See [ADR 0021](../adr/0021-registrar-only-unconsumable-credential-intent.md) and [operator runbook](WEBAUTHN_REGISTRAR_INTENT.md). No signing credential, key verifier or new SQL decision privilege exists.

## V015 — suspend legacy registrar SQL nonce EXECUTE (#51)

`V015__registrar_intent_sql_interlock.sql` is an immutable **forward-only** release interlock. After exact V001–V014 checksum-preserving application, V015 **REVOKES EXECUTE** for `public.issue_reviewer_registration_intent(text,text,text,text,text)` from `temporalmark_credential_registrar_group`, PUBLIC and legacy runtime/provisioning/approver groups. Migration checks assert all four groups remain unable to execute. No registrar login, member, signer secret, RP policy or key is created. The migration owner can still call the LEGACY function for privileged diagnostics: database ownership is NOT human WebAuthn consent or trusted evidence. Do not grant an old SQL login EXECUTE as a workaround; the .NET adapter also explicitly denies and has **no original V013 invocation left**. The previous #49 `registrar-intent` CLI is now intentionally **non-operational**, pending a new cryptographic authorization design, verifier, transactional release and versioned migration (#50/#44). No registered key, FIDO2 attestation or tenant approval is affected. CI and the persistent database regression now expect exactly **15** checksummed migrations. No earlier migration or SHA checksum is rewritten. See [ADR 0025](../adr/0025-fail-closed-registrar-sql-issuance-interlock.md) and [operator stop-line](REGISTRAR_SQL_INTENT.md).

## V016 — deny direct-granted registrar SQL issuance inside PostgreSQL (#51)

A RED integration test temporarily gave the dedicated registrar LOGIN direct `EXECUTE` on the legacy V013 function (simulating an unintended privileged administrator GRANT). Even with V015's group-level REVOKE and the hard-locked .NET adapter, the direct SQL login could still call V013. **Forward-only `V016__registration_intent_owner_only_insert.sql`** adds a separate SECURITY DEFINER INSERT trigger on `reviewer_registration_intents`: it tests the original `session_user` against the independent migration/trigger-function owner `current_user` and raises SQLSTATE `42501` for non-owner callers. A direct EXECUTE grant, role membership or SET ROLE does not change this original SQL login identity. Legacy owner-only V013 diagnostics remain untrusted and have no key, signature, or tenant approval side effect. **Schema owners and superusers can disable the trigger**: this is a security stop-line, not legally immutable evidence. V015 and all previous checksums are unchanged. CI expects **16 immutable migrations**. See [ADR 0025](../adr/0025-fail-closed-registrar-sql-issuance-interlock.md), and do not lift the interlock until a separate independently signed FIDO2/one-time SQL release protocol (#50).
