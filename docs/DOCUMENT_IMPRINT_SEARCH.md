# Exact document SHA-256 imprint search — pilot tenant admin (#112)

**Status: UNQUALIFIED pilot functionality.** An exact document
SHA-256 match means only that the authenticated tenant's registry
contains one or more rows with the same **RFC3161 messageImprint**.
It does **not** independently verify a timestamp signature, prove
a document was delivered, establish a qualified QTSP under eIDAS,
prove legal WORM preservation or show all historical marks exist.
See [ADR 0081](../adr/0081-tenant-document-sha256-imprint-exact-lookup.md).

## API contract and safe use

Authenticated tenant administrators can POST a read-only JSON request
to `/api/v1/stamps/search`:

```json
{
  "fromUtc": "2026-11-01T00:00:00Z",
  "toUtcExclusive": "2026-12-01T00:00:00Z",
  "digestSha256Hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "offset": 0,
  "limit": 50
}
```

The request requires a real signed bearer and an **active PostgreSQL
tenant-admin membership**, as checked by the same `TenantAdminAsync`
logic used for the existing registry. Do **not** include
`organizationId` or `tenantId`: server-side identity alone selects
the tenant. Extra forged fields do not authorize another tenant.
No original document is sent. In a terminal, calculate SHA-256
locally using a trusted hashing utility. Never attach document bytes
or the fingerprint to a query URL, public ticket or application log.

`digestSha256Hex` must contain **exactly 64 ASCII hex digits**, either
case, **without** a `0x` prefix, whitespace or Base64. The business
layer checks the format *before the database call*, decodes 32 bytes
and converts them to the **canonical 44-character padded Base64**
already stored in `timestamp_registry.digest_base64`.
The SQL query filters `organization_id=@org`,
`issued_utc >= @start AND issued_utc < @end`,
`hash_algorithm_oid = SHA256_OID` and
`digest_base64 = @digest`, ordered by `issued_utc,id` with bound
`LIMIT/OFFSET`. Requests are restricted to
`0 <= offset`, `1 <= limit <= 50`; the server reads one extra
row as a bounded `hasMore` indicator.

A representative response:

```json
{
  "items": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "issuedUtc": "2026-11-15T09:00:00+00:00",
      "hashAlgorithmOid": "2.16.840.1.101.3.4.2.1",
      "digestBase64": "ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=",
      "providerId": "pilot-provider",
      "validationState": "Unverified",
      "evidenceReference": null
    }
  ],
  "hasMore": false
}
```

*Illustrative schema, not actual issued evidence.* The response
contains **metadata only**: neither raw `.tsr` DER nor original
documents. To retrieve an individual receipt, use the existing
tenant-scoped `GET /api/v1/stamps/{id}/receipt`, which separately
checks DER/SHA-256 and prepares its audit event before bytes are
served. Search results are not RFC3161/CMS signature validation.
The POST response sets `Cache-Control: no-store`.

## IT/EN admin portal

The dashboard contains a **separate exact SHA-256 search** field,
bounded Search/Previous/Next actions and per-result receipt download.
It applies the currently selected UTC period and active authenticated
tenant. Empty/invalid hex cannot submit. Changing either date,
the input or access token invalidates old search results; late
HTTP responses from previous period/session/search are discarded.
The ordinary 50-row registry pager, daily chart, audit and period
ZIP export continue independently.

## Security and operational limitations

- An imprint is sensitive and can correlate documents. Limit
  visibility to tenant admins; treat request bodies and UI
  telemetry as confidential. This POST reduces ordinary URL/query
  logging but cannot guarantee proxy/body tracing never records
  inputs. TLS, log minimization and authorization remain essential.
- Do **not** treat the match as proof of a signed/qualified
  timestamp. The row is `Unverified` unless later independent
  RFC3161 CMS, trust chain, revocation, Trusted List and UTC(k)
  controls are approved under #15/#13.
- A database owner able to modify both DER and its stored checksum
  may forge internally consistent metadata. The search validates
  retained DER/hash and exact imprint against the query, but **not**
  independent WORM/custody, immutable snapshots or completeness.
  Offset pages can shift if records change during navigation.
  #17 remains OPEN for signed manifests and long-term custody.
- Search itself currently does **not** create a tenant audit record;
  only the subsequent **receipt download** is explicitly audited.
  Per-search query logging/audit, abuse throttling, privacy and GDPR
  review remain operational gaps. Do not label this a fully audited
  evidence-discovery service.
- Tests exercise signed-Keycloak and real PostgreSQL tenant A/B
  canaries with distinct imprints, invalid inputs (400), anonymous
  (401), inactive admin (403), cross-tenant body/header spoofing,
  and a separately mocked browser-only 51-result UX scenario.
  **Browser mocks do not prove SQL isolation**; the genuine
  Keycloak/Pg tests do.

On-prem and Azure use the **same .NET and React code**. No SQL
migration, external dependency, secret, tenant override, QTSP
qualification claim or WebAuthn V015/V016 registrar unblock was added.
The exact final main SHA's 4/4 CI and test evidence are the
acceptance gate before closing focused [#112](https://github.com/KeyserDSoze/TemporalMark/issues/112).
