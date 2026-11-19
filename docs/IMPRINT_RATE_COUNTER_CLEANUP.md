# Manual, owner-only purge of stale search quota metadata (pilot #118)

**Technical minimization, not an approved GDPR deletion schedule or proof of legal storage limitation.** This runbook applies to V020 only. See [ADR 0085](../adr/0085-bounded-owner-imprint-quota-cleanup.md), [ADR 0083](../adr/0083-postgres-atomic-imprint-search-rate-admission.md) and open parents [#115](https://github.com/KeyserDSoze/TemporalMark/issues/115), [#113](https://github.com/KeyserDSoze/TemporalMark/issues/113), [#17](https://github.com/KeyserDSoze/TemporalMark/issues/17).

## Why this exists

V019 enforces 12 valid searches per signed OIDC subject and 30 per tenant per UTC minute using **one writable PostgreSQL primary** shared by all API replicas. It stores exact OIDC `sub` values in `public.imprint_search_rate_principals`. Existing opportunistic cleanup deletes stale rate rows **only when subsequent traffic invokes** the quota function: a tenant that goes idle can leave person-linked counters in PostgreSQL indefinitely. Stamp receipt/evidence retention is a distinct processing purpose and must **not** be conflated with these short-lived admission counters.

Forward-only `V020__owner_only_stale_search_quota_cleanup.sql` adds exactly one manually invoked function:

```sql
SELECT principal_deleted, tenant_deleted
  FROM public.purge_stale_imprint_search_rate_counters(100);
```

The argument is a **mandatory** number of rows per table, strictly **1..500**; NULL, zero, negative and larger batches are rejected with SQLSTATE 22023. The function uses the PostgreSQL database clock and matches V019's cutoff: `window_start < current UTC minute start - interval '3 minutes'`. It independently removes at most the requested count from the tenant+subject and tenant counter tables. `FOR UPDATE SKIP LOCKED` avoids blocking counters currently locked by another transaction; locked rows can remain for the next run. Return columns are **only aggregate deleted-row counts** and contain no identities, tenant UUIDs, searched imprints or JWTs. It does not touch organizations, memberships, search audit, retained DER receipts or evidence custody.

## How an authorized database owner can use it

**Do not run against a customer database without independently approved GDPR purpose, retention/legal-hold and change-control rules.** This example uses **the separately secured migration/schema owner**, not `temporalmark_api`, any HTTP tenant admin or an untrusted service. Do not grant this function to PUBLIC or a runtime/provisioner/approver/credential-registrar group. Store PostgreSQL connection credentials only in approved secret management, never in shell arguments, git, scripts, application logs, or CI artifacts.

1. Back up the database under an approved operational process and check the exact checked-in version **V020** was installed by `scripts/apply-migrations.sh` on the same writable PostgreSQL 17+ primary as the API. Verify `SELECT count(*) FROM public.schema_migrations` is **20** and matches repository checksums; never rewrite V001–V019. Prepare a reviewed maintenance window/permission, rollback/recovery and data protection impact record.
2. In a restricted owner shell with controlled `PGHOST`, `PGPORT`, `PGDATABASE` and `PGUSER` and approved secret injection, run the following **manual** command; output contains only two aggregate counts:

```sh
psql -X -v ON_ERROR_STOP=1 -qAt \
  -c 'SELECT principal_deleted, tenant_deleted FROM public.purge_stale_imprint_search_rate_counters(100);'
```

3. Re-run only within an explicitly approved maintenance operation to drain more than the batch size. A zero/zero return can also mean eligible rows were locked by active transactions, so a single zero result is **not** an independent proof of all-time deletion. Reconcile aggregate counts with reviewed operational observability *without exporting `sub` values or raw row data*. Investigate storage errors rather than trying a privileged role in the normal API.
4. Keep `temporalmark_runtime_group` with **no EXECUTE** on this function (and no direct SELECT/DML on counter tables). The separately owner-invoked function is `SECURITY INVOKER`, with a fixed safe search path and qualified table references; the original V019 quota and #114 audit API continue unchanged. The operator/DB owner still has broad schema privileges and needs independent control.

## Concurrency, deployment parity and unresolved guarantees

The routine operates on the same underlying PostgreSQL database; it is **not** a scheduler, autonomous retention service or cross-region distributed cleanup. The V019 live quota gate and its row locks remain authoritative; only counters strictly older than the shared cutoff are eligible. A rolled-back DB clock makes newer windows ineligible rather than forcing deletion. The same SQL is available on OSS/on-prem PostgreSQL and managed Azure PostgreSQL 17, but **Azure Terraform does not yet wire a migration job or maintenance scheduler**.

Remaining open under #115/#113: independent legal/GDPR retention and DPIA, access and deletion rights, backups/snapshots and restore reappearance, automatic cadence/failed-job alarm and operator approval, production Azure/ingress and on-prem proxy logs, edge/pre-auth throttling, multi-primary governance and subject pseudonymization. This manual function does **not** complete any of those responsibilities. Unqualified pilot evidence remains `Unverified`; eIDAS/QTSP, UTC(k), WORM or CAB/AgID conformity is not inferred.

## Disposable CI test boundary

`ImprintSearchRateCleanupPostgresTests` creates new synthetic organizations on the disposable CI PostgreSQL 17 volume. It inserts a distinct search audit, populates V019 counters through the restricted runtime function, adjusts only those **test tenant** windows, and requires that the owner-only V020 function remove old actor/tenant state while preserving current counters, original organizations and append-only tenant audit; invalid batch and runtime EXECUTE attempt must be denied. No test changes or deletes real customer evidence. The Docker CI replays and checks **20 versioned migrations**, full logical PostgreSQL backup/restore and signed-Keycloak two-tenant HTTP regressions. Close only scoped #118 after independently checking the **exact final docs-inclusive main SHA** 4/4 CI and actual Postgres test logs.
