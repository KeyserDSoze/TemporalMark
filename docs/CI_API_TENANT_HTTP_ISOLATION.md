# Real signed-Keycloak and PostgreSQL two-tenant HTTP API isolation — #82

**Scope:** disposable developer/CI backend only. ADR [0051](../adr/0051-ci-real-api-cross-tenant-keycloak-postgres-isolation.md). Parents [#20](https://github.com/KeyserDSoze/TemporalMark/issues/20) and [#14](https://github.com/KeyserDSoze/TemporalMark/issues/14) remain OPEN for production RLS, IdP assurance, WORM and tenant isolation beyond these routes.

## Boundaries and authentic fixtures

The existing Docker Compose development API listens on `127.0.0.1:8080`, Keycloak on `127.0.0.1:8081`, PostgreSQL on `127.0.0.1:5432`. The Python stdlib harness `tests/integration/api-tenant-isolation.py` is invoked only from `docker-smoke` with `TEMPORALMARK_CI_API_ISOLATION=1`, fixed literal loopback origin/issuer and a public OIDC discovery issuer check. It sends HTTP requests to **actual compiled ASP.NET Core middleware and database-backed authorization**, never a mock or locally signed JWT. Tokens are fetched as Keycloak-issued signed access tokens through **CI-only** password grant; no production auth policy is relaxed.

Two independent demo accounts are signed by the development realm: existing `demo-admin` for A (`11111111-1111-1111-1111-111111111111`) and new dedicated `demo-tenant-b` for B (`22222222-2222-2222-2222-222222222222`). The development-only test client now emits the user's own `organization_id` *access token* claim and the existing realm `role` and API audience; it never permits selecting an arbitrary tenant. Separate new development Keycloak subjects include a nonadmin `tenant_member`, a signed B `tenant_admin` subject with inactive **database** membership, and a signed admin with no organization claim. Two other explicit **CI-only** Keycloak clients mint a genuinely signed token with the wrong audience and a 3-second authentic Keycloak-issued bearer, respectively. A signed master-realm token independently tests wrong issuer. No passwords, JWTs, OIDC codes, OTP values or sessions are logged.

After verifying pre-seed B admission returns `403`, the CI test uses only the existing **disposable local PostgreSQL owner** via `docker compose exec ... psql` to call the already installed `bootstrap_organization`, insert B's inactive second membership and A/B *synthetic* timestamp and audit canaries. The registered rows have distinct SHA256-verified but **not authentic RFC3161** DER-like bytes with `Unverified` state. No elevated SQL user, public bootstrap endpoint, production migration or access-control bypass is added. App HTTP requests still use the restricted `temporalmark_api` SQL login. CI's existing `Tear down` runs `docker compose ... down -v` on the disposable stack, including both canary rows and imported demo users.

## Acceptance matrix and fail-closed distinctions

- Anonymous requests to `/api/v1/me`, registry list, summary, audit, period export, evidence receipt and issue return **401**; malformed bearer also returns **401**.
- Valid signed Keycloak JWT with wrong API audience, wrong issuer, and a genuinely expired short-lived token return **401** (unauthenticated). Strict API `TokenValidationParameters.ClockSkew=TimeSpan.Zero` is required to avoid the default five-minute grace; keep clocks synchronized.
- Signed but nonadmin, missing organization claim, inactive DB membership or B identity before B has a persisted organization return **403** (authenticated but not authorized).
- Both A and B get only their own canary from list/summary, own TSR byte download and ZIP manifest+payload. Cross-tenant receipt IDs return **404** indistinguishable from absent IDs; audit listings and prepared access audits are organization-isolated. Evidence response headers must contain `Cache-Control: no-store`.
- Forged organization IDs in query and headers on registry/summary/audit/export and in issue JSON body never change the signed server-selected tenant; authorized issue stays **503** while no external TSA is configured, unauthorized issue **403**, and no new record appears. All proof is scoped to the disabled-provider pilot.

## Reproduction and safety

After starting the **disposable local** Compose stack and migrations (never a production environment), run only from the repository root:

```sh
TEMPORALMARK_CI_API_ISOLATION=1 python3 tests/integration/api-tenant-isolation.py
```

Do not reuse test passwords/realm config outside local development. Because this script seeds owner-controlled canary records and pilot audit append-only rows, **DO NOT run against persistent customer volumes**. CI destroys the disposable volume. Direct local re-runs require a fresh test volume; do not bypass the append-only audit triggers to clean real data.

## TDD chronology

- [RED CI 43892292576](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43892292576), commit `46cbfc2`: real Keycloak denied the nonexistent B CI principal, after all preexisting smoke checks succeeded.
- [Fixture CI 43893706831](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43893706831), commit `582102e`: Keycloak exposed `resolve_required_actions` for the new incomplete development identities, rather than accepting the fixture or testing the API. Corrected complete development user profiles and pinned test serialization/expiry policy.
- Final full four-job acceptance and exact SHA to be recorded in [issue #82](https://github.com/KeyserDSoze/TemporalMark/issues/82) **only after observed success**.

**Nonclaims:** not HTTP evidence of global RLS, IdP live revocation/identity governance, actual FIDO human consent, registered QTSP qualification, immutable evidence, signed WORM custody or validated external TSA. Security #64/#61/#57/#50/#44/#38/#17/#13 and V015/V016 fail-closed interlocks remain unchanged.
