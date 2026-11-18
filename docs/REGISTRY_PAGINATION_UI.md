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
