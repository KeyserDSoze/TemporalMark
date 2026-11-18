# Dashboard: authenticated tenant-only UTC daily counts (#110)

**Pilot statistics only.** These are counts of registry records, **not**
independent proof that a qualified TSA issued them, that all records
were preserved under WORM, or that the underlying SQL state is authentic.
Parent #14/#17/#13 stay open. See [ADR 0079](../adr/0079-tenant-utc-daily-dashboard-counts.md).

## Existing total, new daily breakdown

The current React IT/EN admin dashboard already uses
`GET /api/v1/stamps/summary` for the exact number of registered marks
within a selected UTC period. New endpoint
`GET /api/v1/stamps/daily?fromUtc=2026-11-01T00:00:00Z&toUtcExclusive=2026-12-01T00:00:00Z`
provides a daily breakdown *without deriving it from the first 50
visible list items*. Response structure:

```json
{
  "organizationId": "11111111-1111-1111-1111-111111111111",
  "fromUtc": "2026-11-01T00:00:00+00:00",
  "toUtcExclusive": "2026-12-01T00:00:00+00:00",
  "days": [
    {"dateUtc": "2026-11-01", "count": 0},
    {"dateUtc": "2026-11-02", "count": 2}
  ]
}
```

Illustrative JSON above is a **partial example only**; actual responses
include all days in the requested interval, including zero-count days.
Each `dateUtc` is the ISO-8601 UTC calendar date; the start is
inclusive and the end is exclusive.

## Security / limits

- Requires a **verified signed OIDC bearer**, an authoritative *active*
  tenant-admin membership in PostgreSQL, and server-selected
  `organizationId` from the verified token and DB. No tenant ID
  passed as a query string, header or JSON field can override this.
  Anonymous/bad tokens -> 401, non-admin/inactive membership -> 403.
- Both bounds must be **exact UTC midnight**, period **1–31 complete
  UTC days**. Bad/too-wide/nonmidnight -> 400 before any aggregate
  database call. React requests daily data only for such periods;
  longer filter selections continue to load the **existing exact total,
  first 50 registry records, audit and export** without failure.
- PostgreSQL executes a single parameterized, tenant-filtered
  `WHERE organization_id=@org AND issued_utc>=@start AND
  issued_utc<@end` aggregation, grouping by
  `(issued_utc AT TIME ZONE 'UTC')::date`. The explicit UTC
  conversion prevents results varying with PostgreSQL session
  timezone. `date` is read via Npgsql `DateOnly`, and the business
  layer fills absent UTC dates with zero. Duplicate/out-of-range/
  nonpositive result groups fail closed rather than being displayed.
- The frontend displays per-day counts in an accessible bar chart,
  with IT/EN labels and explicit **NOT qualified** context. This
  consumes only counts, never original documents, unsigned payload
  blobs, signers, private tenant imprints or raw evidence.

## Verification / remaining gaps

Business xUnit includes tenant B boundary and UTC midnight/31-day
range tests; the disposable Docker CI uses a real Keycloak signed
two-tenant fixture with PostgreSQL canary rows and API 401/403/400
checks. Test-first sources were committed before production, and
**CI results must be read per exact commit**, not inferred from
source. Live totals/daily results are registry aggregates, not an
independent audit, billing reconciliation, hash chain, global
snapshot, complete retained-evidence proof or qualified TSA/legal
certification. SQL RLS, identity governance, WORM object lock,
signed custody and CAB/AgID qualification stay under #14/#17/#13.
The V015/V016 WebAuthn registrar stop line is unaffected.

References: [Npgsql date mappings](https://www.npgsql.org/doc/types/basic.html);
[PostgreSQL datetime operators](https://www.postgresql.org/docs/current/functions-datetime.html).
