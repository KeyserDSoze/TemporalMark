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

### Integration ordering regression and correction

[CI 43895442047](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43895442047), commit `d12099b`, **passed the entire new real signed-JWT / two-sided tenant HTTP test** after the complete synthetic Keycloak profiles and strict API token expiration change. The final *existing* `authenticated.spec.ts` PWA smoke then failed because the new tenant test had **already seeded an A canary record**, while that preexisting browser test explicitly expects an empty registry (`Nessuna marca registrata nel periodo selezionato.`). This was a test-fixture lifetime/order conflict, not an API cross-tenant failure.

Do **not** weaken the original empty-dashboard browser test or delete append-only audit rows to mask the fixture. Run the existing `OIDC admin login and disabled external TSA smoke` **before** the new canary-seeding `api-tenant-isolation.py` step, then execute the new HTTP matrix as the **last functional** step before diagnostics/volume teardown. Preserve `if: always()` cleanup in CI. Only final exact-main four-job GREEN is acceptance evidence.

## Complete actual GREEN evidence and documentation-inclusive HEAD gate

[CI 43897042542](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43897042542) on SHA `dfbbe87fdc2506afc5763ecce95cad398e4a147a` completed with **all four jobs SUCCESS**. In Docker smoke the preexisting authenticated browser empty-dashboard test, real PostgreSQL migration and full `pg_dump` / `pg_restore` sealed-witness rollback, Keycloak registrar + reviewer real browser TOTP/PKCE live role test, and the new full real HTTP A/B signed-JWT `401/403`, cross-receipt `404`, no-store ZIP/TSR and canary audit isolation test ALL report SUCCESS. The restricted API remained fail closed with no external TSA. This is a real integration success, not a claim of all-product RLS or legally qualified timestamps.

After this documentation update, GitHub Actions must run once more on the *new exact final `main` SHA* before closing the child; the issue records that exact final run. Parent #20/#14 and independent FIDO, reviewer/registrar, evidence/WORM and legal qualification blockers remain OPEN.

## Bounded UTC daily dashboard stats — #110 (child #14)

The same disposable signed-Keycloak + real PostgreSQL/ASP.NET Core
two-tenant isolation test now also covers authenticated
`GET /api/v1/stamps/daily`, **not a mock endpoint**. The existing
`seed_ci_canaries()` writes one synthetic `Unverified` timestamp
for each tenant with `issued_utc=now()`. The test chooses a three-day
explicit **UTC midnight** interval around the test UTC date and
requires a zero-filled three-row series whose **sum is exactly 1
for each independently signed tenant administrator**, regardless of
another tenant's canary. It spoofs organization IDs in both query
parameters and HTTP headers and requires the result to remain
scoped to the signed JWT and active PostgreSQL membership.

The same script asserts anonymous API requests return 401, disabled
signed tenant-admin membership returns 403, and nonmidnight or more
than 31-day inputs return 400. The existing receipt/ZIP/audit and
negative identity checks are retained; no additional bootstrap
credentials, third-party HTTP destinations, sensitive token logging,
production data, DB owner rights for the API, or fake signed-token
helper is introduced. The underlying query groups by PostgreSQL
`(issued_utc AT TIME ZONE 'UTC')::date` with
`organization_id=@org` and a bounded half-open period; the UI
never estimates the trend from its first 50 records.

The real browser test `tests/frontend/authenticated.spec.ts`
additionally checks that the authorized **empty pilot** dashboard
renders exactly 30 accessible zero-day bars by default, and that
selecting a longer range hides only the graph while retaining
registry, export and audit controls. The CI docker-smoke workflow
must actually pass with compiled API and real signed Keycloak for
these assertions to constitute evidence. Older successful runs
do not prove the new #110 route or frontend logic. This remains
**unqualified registry counts**, not legal issuance/retention proof
(ADR [0079](../adr/0079-tenant-utc-daily-dashboard-counts.md)).

## Browser date-filter regression found and corrected in #110

The final documentation-inclusive candidate [`83372ec`](https://github.com/KeyserDSoze/TemporalMark/commit/83372ec878887e3293ed1532832f435fd902f089)
ran [GitHub Actions 44296880404 attempt 1](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44296880404/attempts/1).
The **backend, frontend and Terraform jobs succeeded**, but the real
signed-Keycloak `docker-smoke` browser job failed in
`tests/frontend/authenticated.spec.ts` after exercising the new
over-31-day chart fallback. The test had selected
**2026-01-01 through 2026-03-01**, then prepared a new ZIP export on
**2026-11-18** and incorrectly expected the just-created `PeriodExportPrepared`
audit event to appear **inside the old January–March audit filter**.
The API correctly returned the in-range audit results only; this is
a test-sequencing error, not a justification to weaken tenant/UTC
audit isolation.

The browser fixture fix [`60d59b3`](https://github.com/KeyserDSoze/TemporalMark/commit/60d59b3ab9c5eff084c8ed8a3b6f4b4c9f2b5fe8)
explicitly resets the selected period to the **current 30-day UTC
window**, waits for the zero-day chart to reappear, and **only then**
downloads the ZIP and checks the newly prepared in-period audit
event. The long-range fallback and standard chart assertions are
preserved. No API audit query, OIDC rule, SQL scope, WORM or legal
qualifying assertion was changed. Final exact HEAD 4/4 CI must be
independently verified before closing focused issue #110.

## Exact document SHA-256 imprint search over genuine tenant HTTP/SQL (#112)

The disposable signed-Keycloak + PostgreSQL two-tenant CI harness now
exercises **read-only `POST /api/v1/stamps/search`** with the
document-imprint SHA-256 hex in a **JSON body**, never in the URL.
The existing synthetic A/B registry canaries have distinct 32-byte
imprints and current UTC issuance time, with `Unverified` evidence.
For each **independently Keycloak-signed active tenant admin**,
the test requires:
- own hex imprint (both cases) -> one own receipt's **metadata only**
  and `hasMore=false`; no `ResponseDer` JSON;
- other tenant's imprint -> **zero** results, despite the other
  tenant's real database row;
- `offset=1,limit=1` -> no unexpected foreign result;
- attempts to forge `organizationId/tenantId` in both JSON
  payload and HTTP headers -> still **own** tenant's result;
- malformed/missing/overlong/nonhex imprints, `limit=51`,
  negative offset -> 400; anonymous -> 401, disabled tenant-admin
  membership -> 403. Existing signed issuer/audience/expiry
  and real member-role restrictions are unchanged.

This is not a mocked API or JWT: the container tests run a real
.NET 10 endpoint, live Keycloak signature validation and an actual
PostgreSQL tenant-filtered query using the API's restricted DB role.
The separate Playwright fixture first completes genuine OIDC
authentication/export checks, then **mocks only search response
metadata** for 51 synthetic results to verify browser input validity,
Next/Previous and reset on period changes. These mocks provide
**UI behavior evidence only**, not SQL isolation.

The search POST is **not** a new TSA issuance operation or a
legal/eIDAS timestamp validator. With #114 / V018 the same API also appends a separate minimized
tenant/actor search event before returning any match metadata; receipt
downloads remain separately audited. CI verifies exactly four valid
search events for each signed-Keycloak tenant, zero for seven malformed
requests, no raw imprints or match metadata in audit, and a reversible
CI-only PostgreSQL runtime INSERT-revocation probe that must return
HTTP 500 without match data. A finally block restores the SQL grant. Refer to [ADR 0081](../adr/0081-tenant-document-sha256-imprint-exact-lookup.md)
and [operator guide](DOCUMENT_IMPRINT_SEARCH.md). Any CI claim of
completion must be checked on the **exact final docs-inclusive
`main` SHA** using all four core jobs; older successful test runs
must not be reused for later source commits.

## Tenant + principal search quota and 429 regression (#116)

After verifying real two-tenant Keycloak-signed search audit (#114), the disposable API test repeatedly sends valid SHA-256 document-imprint JSON searches under tenant A's genuine signed admin bearer. Its **V019 SQL function** must admit only the remaining portion of that actor's 12-per-UTC-minute budget, then respond 429 with a numeric 1–60-second `Retry-After`, no-store and no match/imprint metadata. Spoofed B tenant IDs in body/headers must not reset the quota; malformed document hex still returns 400 *before* the limiter; tenant B's signed bearer and real PostgreSQL registry remain independently usable. Every 200 successful lookup must still append the privacy-minimized #114 tenant audit, while 429/malformed requests append none. The earlier real revoked-audit-INSERT test must still return HTTP 500 without matching data.

A distinct xUnit real-Postgres suite verifies 12 actor and 30 tenant limits, 72 parallel SQL calls from six principals in one tenant, expiry, 22023 future-clock rollback denials and restricted runtime-role SELECT privileges. CI expects 19 checksummed migrations. These tests are **not** proof of multiple writable PostgreSQL primaries, release configuration in Azure, reverse-proxy body-log redaction, GDPR retention approval or signed WORM audit. See [ADR 0083](../adr/0083-postgres-atomic-imprint-search-rate-admission.md) and [operator runbook](IMPRINT_SEARCH_RATE_LIMITING.md).
