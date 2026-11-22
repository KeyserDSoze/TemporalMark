# Tenant administrator: navigate the timestamp evidence registry (#111)

**Nonqualified pilot registry browsing**. Source: [ADR 0080](../adr/0080-admin-tenant-registry-pagination-and-stale-request-gate.md);
tracked under [focused #111](https://github.com/KeyserDSoze/TemporalMark/issues/111)
and open parent #14. This is *not* an immutable complete-period legal
export, signed WORM record or independently qualified timestamp verifier.

## Existing authenticated API and new UI control

The already-supported authenticated `GET /api/v1/stamps` accepts:

```text
GET /api/v1/stamps?fromUtc=...&toUtcExclusive=...&offset=0&limit=50
GET /api/v1/stamps?fromUtc=...&toUtcExclusive=...&offset=50&limit=50
```

The .NET Business service enforces `offset >= 0`, `1 <= limit <=
200`, tenant scope and SHA-256 local DER consistency; the PostgreSQL
repository uses bound `@org`, `@start`, `@end`, `@limit` and
`@offset` parameters with deterministic `ORDER BY issued_utc,id`.
**The tenant is derived from the authenticated OIDC bearer plus an
active tenant-admin database membership, not from an HTTP header,
query string or React state.** Counts come from the distinct
`/stamps/summary` API, not the page length.

The IT/EN dashboard can now navigate receipt pages of **50** via
accessible **Previous / Next** buttons, showing a range such as
`1–50 of 51` or `51–51 of 51`. It disables Previous at offset zero
and Next when it reaches the recorded total or a short page. The
user can still download a retained `.tsr` receipt, filter periods,
review the daily UTC graph and audit, and export up to the synchronous
ZIP limits.

## Asynchronous browser state and session boundaries

Changing **either UTC date filter** or the access token resets the
registry offset to zero. React coordinates summary, list, audit and
optional 31-day daily count as **one request generation**, parses
responses, then commits a whole batch only when that generation is
still the newest. Late replies from old periods, old offsets,
unmounted components or prior access tokens must not overwrite the
latest visible page; loading and errors hide previously fetched
tenant data, and the UI guards rendering by the token that actually
fetched it. Server OIDC and SQL authorization **remain authoritative**;
this visual safety guard is not a substitute for independent live
account/role governance or PostgreSQL row-level security.

## Evidence and known gaps

A real signed-Keycloak / PostgreSQL two-tenant HTTP CI harness continues
to verify strict server-side tenancy. It now additionally checks
`offset=1,limit=1` against each tenant's one-record disposable
canary, invalid negative offset / over-200 limit (400), and forged
tenant query/header controls. An authenticated browser regression
executes genuine OIDC and receipt/export checks **before installing
any test-only route mocks**. Those mocks return 51 *synthetic*
records solely to exercise UI Next/Previous navigation, displayed
ranges, the date-filter reset and a deliberately delayed old-page
response. **UI mocks do not prove SQL isolation**; only the separately
run, genuine API/DB tests do.

**Residual limit:** offset pagination is not an atomic snapshot of a
changing table. Concurrent insertion/deletion can shift rows between
pages, causing omissions or duplicates across a multi-page browsing
session. The controls do not provide a keyset cursor, stable high-water
witness, signed manifest or full-period export completeness. This
remains #17; tenant onboarding/RLS/real privileged identity assurance
remain #14/#23, and qualified TSA/eIDAS/legal CAB controls #15/#13.
No Azure-only package, API privilege, database migration or
WebAuthn V015/V016 registrar bypass was introduced. Pilot receipts
stay **`Unverified`**.

## TDD and CI checkpoint

ADR 0080 first, test-only Playwright source `357958c`,
signed-Keycloak API integration bounds `7fb2030`, React changes
`fbac448`, localized IT/EN labels `9dfaa92` and
delayed-page browser regression `292a508`. The initial tests-only
[Actions 44300954775 attempt 1](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44300954775/attempts/1)
was **RED** on the missing `1–50 di 51` UI, with prior code
backend/frontend/Terraform successful and the real browser failing.
**No GREEN is assumed** until exact final docs-inclusive main SHA's
backend/frontend/docker-smoke/terraform conclusions and real tests
are independently verified.


## Bounded and ordered Business read boundaries (#168 / ADR 0126)

PostgreSQL already uses `ORDER BY issued_utc,id LIMIT @limit OFFSET @offset` for tenant registry pages and exact-imprint searches. The Business service now independently **fails closed before returning any metadata** if a buggy/alternate repository delivers more than the selected page limit (1–200) or if its returned rows violate strictly increasing `(IssuedUtc, canonical UUID)` order. Exact-imprint search already limits the batch to `limit + 1` (1–50 results plus one lookahead) and now validates the **entire** batch's order, including the additional `hasMore` lookahead, before it can disclose matches or page state. Existing tenant, period, `Unverified`, DER/SHA256, duplicate-ID and imprint gates remain. Generic errors disclose no row, provider, tenant or searched imprint. The API/React pagination contract and on-prem/Azure code remain unchanged.

[ADR 0126](../adr/0126-fail-closed-registry-page-and-imprint-search-order.md) / [#168](https://github.com/KeyserDSoze/TemporalMark/issues/168): genuine [tests-only RED 45056357292](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45056357292/attempts/1) with **five missing-denial failures / 285 Business passes** (including sorted UUID-tie positive); minimal post-RED service [`216ae1b`](https://github.com/KeyserDSoze/TemporalMark/commit/216ae1b1257bbea7d2049dad3d4dd9b93800d3e8). Verify exact docs-inclusive GREEN separately. **One valid batch is not a multi-page stable snapshot**: inserts/deletes between separate offset reads may still shift page boundaries. Nor is it a signed complete-period export, WORM, legally qualified TSA or independent audit witness. #14/#17/#15/#13 remain OPEN.


## Retained DER resource limits even for metadata-only pages (#171)

The authenticated tenant-admin registry list (1..200 rows/page) and document-imprint search (1..50 rows plus **one** `hasMore` lookahead) return JSON **without raw DER**, but the .NET Business layer still loads the retained DER to confirm the stored SHA-256. It now applies **1 MiB per stored receipt and 64 MiB total per returned read batch** before CPU-intensive hashing, **after** validating all tenants and UTC periods, including the search lookahead. An invalid batch fails as a whole without partial disclosure. A 200-row page consisting of many valid 1MiB receipts can exceed 64MiB; use a smaller `limit`/narrower UTC interval until a genuinely streaming registry read is available. These are **pilot resource limits** and do not make offset paging a snapshot or qualified evidence verifier.

The synchronous ZIP already has the same budgets with its separate `ExportTooLargeException`, and individual GET receipt retains a different 409/no-store behavior. No public page DTO or UI navigation, PostgreSQL query or per-tenant role is changed. [ADR 0129](../adr/0129-bounded-page-and-search-der-before-hashing.md) / [#171](https://github.com/KeyserDSoze/TemporalMark/issues/171). Genuine tests-only [RED 45066373120](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45066373120/attempts/1) confirmed three missing-denial assertions and 298 passes; source only afterward [`6bc8c1a`](https://github.com/KeyserDSoze/TemporalMark/commit/6bc8c1a73c2deacdeaaabdb0262f9150d705dde1). **Final docs-inclusive CI GREEN must still be verified.** Rejected legacy rows still consume DB/network bytes **before** reaching the Business guard; full protected streaming, signed WORM and complete-period legal retention stay open.


## Metadata-only read now gates PostgreSQL's DER wire projection (#172)

Real PostgreSQL registry `PageAsync` (1..200) and exact document-imprint `SearchByDigestAsync` (1..51, counting search lookahead) **no longer ask PostgreSQL to project unbounded original `response_der` values into Npgsql before the #171 Business byte budget can run**. [ADR 0130](../adr/0130-snapshot-bound-postgres-registry-der-projection.md) uses one statement/snapshot: selected IDs and logical byte lengths in a materialized CTE, an all-rows per-token <=1MiB and cumulative <=64MiB admission, then a `CASE` yielding original DER only for an entirely accepted batch, otherwise `NULL::bytea` for every row. A NULL result causes generic fail-closed read before `GetFieldValue<byte[]>`, never a partial page or misleading search `hasMore`. The view can retry with a **smaller limit/date period** only for valid stored data; a too-long legacy token is not made valid by changing page size. The original business tenant/UTC, SHA256, `Unverified`, unique/order/imprint checks remain, as do #169 single GET 409/no-store and synchronous ZIP 413. Same shared SQL for OSS and Azure, no React UI or API shape change.

Real PG17 [RED 45070013421](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45070013421/attempts/1) had three precise missing-denial failures/248 passes (251 total) before minimal source [`198e855`](https://github.com/KeyserDSoze/TemporalMark/commit/198e855364e0eabf01a88ba93edb3fb904d3529e). Final docs-inclusive GREEN must be independently verified before closing #172. TOAST/storage reads and concurrent accepted requests are not resource-bounded by this change; eventual truly streaming exports, stable snapshots and legal WORM/qualified timestamp verification remain separate.
