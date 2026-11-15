# ADR 0006 — Transactional tenant bootstrap and deferred administrator integrity

Status: Accepted (2026-11-15)

Related: #14, #22, ADR 0003, `docs/THREAT_MODEL.md`.

## Problem
The original PostgreSQL BEFORE trigger only protected deletion/demotion of an *existing* last administrator. It allowed active organizations to be created without any administrators; a plain count under concurrent transactions is also unsafe without serialization. The initial local schema was installed through PostgreSQL init scripts, and existing volumes/Azure instances require an incremental, non-destructive upgrade.

## Decision
- Enforce the invariant **at transaction commit** with PostgreSQL `CONSTRAINT TRIGGER ... DEFERRABLE INITIALLY DEFERRED` on organization creation/activation and membership insert/update/delete. The final state of every *active* organization must include at least one active `tenant_admin`. Inactive organizations may temporarily have none and cannot reactivate without an admin.
- Serialize membership mutations by physically updating the parent `organizations.membership_epoch` tuple inside a BEFORE trigger. Parent tuple updates serialize concurrent changes; `READ COMMITTED` transactions wait and then validate against the committed state, while `REPEATABLE READ/SERIALIZABLE` conflicts may abort with `40001`. Callers must retry the **whole** business transaction on serialization failure, never just the last statement. Multi-organization reassignment updates parent rows in UUID sort order.
- Expose `public.bootstrap_organization(uuid, text, text)` for **privileged, controlled operator provisioning only**; inserts the organization and initial admin as one atomic SQL statement. Grant `EXECUTE` explicitly to a separate operator/provisioner DB role after out-of-band OIDC validation. `PUBLIC` has no execute privilege. **Do not expose it as a public REST endpoint or grant it to the API runtime role.** Never take tenant ID or first-admin subject from an unauthenticated browser request.
- PostgreSQL validates subject syntax/length and absence of control characters. **SQL cannot cryptographically establish that a `sub` exists or was issued by the trusted OIDC issuer.** Verifying the subject against the configured IdP remains an external, mandatory enrollment control; the current operator-only mechanism is not a complete automatic onboarding flow.
- Apply versioned, SHA-256-checksummed scripts `V001`–`V003` using `scripts/apply-migrations.sh`. A transactional advisory lock serializes migration runners, and altered scripts with applied versions fail closed. Historical migrations are immutable; new changes require a new `V00N` file. Missing initial schema is created by `V001`; existing dev volumes are upgraded in place. The development Compose `migrate` service completes before API startup; Azure/on-prem production must run a separate controlled migration job before deploying the API.

## Concurrency and recovery boundaries
- The trigger guarantees the invariant only while database triggers, foreign keys and constraints are enabled and DML is issued by restricted roles. Owners/superusers can disable triggers; production must use different migration-owner, provisioning and API identities with least-privilege grants and independent DBA oversight.
- The migration rejects pre-existing active organizations with no active admin; the database operator must investigate and repair those *before* applying `V003`, with approval and audit evidence.
- Production migrations require a verified backup and restore plan, tested rollback strategy and approval; this proof is not delivered by development CI.
- Bootstrap records are not sealed in the pilot audit table and the first subject is not automatically provisioned into the IdP. For a usable organization, an approved identity administrator must also configure valid OIDC claims/mapping.
- No tenant membership/administration REST endpoints, invitation flow, multi-organization selection, RLS, privilege audit/4-eyes workflow or platform operator permissions are introduced in this slice. Keep #14 open.

## Standards and implementation references
- PostgreSQL constraint triggers: https://www.postgresql.org/docs/17/sql-createtrigger.html
- PostgreSQL deferral: https://www.postgresql.org/docs/17/sql-set-constraints.html
- PostgreSQL isolation and serialization failures: https://www.postgresql.org/docs/17/transaction-iso.html

Source: independently reviewed PostgreSQL reference behavior; validation via concurrent Npgsql integration tests in GitHub Actions.
