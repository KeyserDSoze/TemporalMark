# ADR 0113 — Reject direct runtime EXECUTE grants on reviewer rejection and challenge issuance before Entra API listen

Status: **Accepted for a scoped, test-first opt-in pre-listen ACL guard [#148](https://github.com/KeyserDSoze/TemporalMark/issues/148)**, 2026-11-21. Parent #128 Azure Entra production, #14 tenancy, #50 registrar, #18 Azure CAB, #17 WORM, #13/#15 legal/QTSP and #38 independently signed reviewer action remain OPEN. No real Azure staging/apply or legal qualification claim.

## Reviewed baseline and risk

Read ADR 0001/0009/0015/0016/0099/0100/0112; `docs/ROADMAP.md`, `docs/POSTGRES_RUNTIME_PRIVILEGE_PREFLIGHT.md`, `docs/API_POSTGRES_ENTRA_PRELISTEN_CANDIDATE.md`, `docs/THREAT_MODEL.md`, V010/V012 immutable migrations, the real PG17 `PostgresRuntimePrivilegePreflightTests.cs` disposable-login fixture and the single read-only catalog `PostgresRuntimePrivilegePreflight.Sql`. PostgreSQL 17 [GRANT](https://www.postgresql.org/docs/17/sql-grant.html) and [access privilege inquiry](https://www.postgresql.org/docs/17/functions-info.html) distinguish role membership from effective function EXECUTE (which can derive from a direct grant, another inherited role or PUBLIC).

ADR 0112 guards seven elevated functions plus bootstrap functions, but does **not** inspect two V010/V012 `SECURITY DEFINER` routines. Both are intended only for the independent reviewer SQL approver role, and may accept a sensitive original-review scope even without reviewer-held WebAuthn proof:

- `public.reject_enrollment(uuid,text,text,text,text,text,char(64),char(64),text)` — V010 terminal reject with reviewer proof digest and reason; SQL EXECUTE is reviewer-only.
- `public.issue_reviewer_decision_challenge(uuid,text,text,text,text,text,char(64),text,text)` — V012 creates a random, **unsigned and unconsumable** challenge bound to original pending review; SQL EXECUTE is reviewer-only.

Even a login with no membership in `temporalmark_approver_group` can acquire EXECUTE through an accidental direct function grant. Such a misgrant could evade the current point-in-time check; it is **not evidence that an Azure misgrant exists**.

## Decision and required test-driven sequence

1. **RED first on main, after this ADR and before modifying production source:** add two fixed `InlineData` cases to the existing real PostgreSQL17 `DirectPrivilegedFunctionExecuteGrantMustNotPassEntraRuntimePreflight` tests. Keep distinct randomly named test-only LOGIN, only runtime-group membership, one *direct* EXECUTE grant per role, baseline pass and expected denial, generic no-inner/no-secret failure, `Pooling=false`, and `finally` cleanup of grant, membership and role even when expected RED. Do not execute any privileged function or mutate tenant, review or migration data. Observe exactly 2 missing-denial xUnit failures while the existing 146 PG tests remain green (148 total); unrelated red does not count.
2. Only after a verified RED add exactly two static, fully typed `AND NOT pg_catalog.has_function_privilege(...,'EXECUTE')` predicates to the existing **single read-only** preflight `SELECT` on the *already authenticated session*. Keep all existing function/table/column/role denies and intentionally allowed `public.consume_imprint_search_rate(uuid,text)` runtime admission. No SQL migration, app endpoint, SQL role/grant manipulation, Terraform or default OSS Password-mode change.
3. Update operator preflight, Entra pilot, reviewer provisioning, migrations, THREAT_MODEL and ROADMAP; record actual test/CI evidence. Only close #148 after exact final docs-inclusive main SHA has GitHub CI backend, frontend, terraform and docker-smoke 4/4 SUCCESS, ci-verdict success and `temporalmark/ci-4-core-jobs=success`; 148 real PG17 tests, unchanged 20 migration checksums, full dump/restore, Keycloak OTP/PKCE and tenant A/B negative authorization, Nginx 413/414/429 privacy.
4. Revoke an actual misgrant only through independently approved SQL-owner change control. Never weaken/disable this prelisten guard merely to make startup succeed.

## Residual limits

Only explicit `ContainerAppsEntraCandidate` in ASP.NET Production runs this *once*, before HTTP bind. It cannot detect post-start GRANT drift, prevent owner bypass or table mutation through unknown/future objects, verify real Azure Entra runtime identity/SQL role or replace application-layer signed OIDC/strong human consent. Both V010 rejection and V012 challenge issuance are **not cryptographically signed independent decisions**; the older SQL review-grant bypass remains #38/#35/#31. Real nonadmin Azure PostgreSQL and admin-password Terraform-state cleanup remain #128/#18; on-prem SQL deployment equivalence needs independent assessment. Ordinary PostgreSQL rows are not legally WORM or evidence of eIDAS qualified TSA/QTSP status; #17/#13/#15 still open.
