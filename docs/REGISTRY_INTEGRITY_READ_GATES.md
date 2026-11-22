# Timestamp registry read gates: page and period export integrity (#105)

**Scope: local evidence consistency of the unqualified pilot registry. NOT
WORM preservation, certified archiving, qualified TSA validation or an
independent audit witness.** Read [ADR 0074](../adr/0074-registry-page-export-integrity-and-unique-ids.md)
and open [parent #17](https://github.com/KeyserDSoze/TemporalMark/issues/17).

## Operator-facing behavior

The authenticated `GET /api/v1/stamps` page and
`GET /api/v1/stamps/export` remain scoped to the **tenant derived from
verified OIDC claims plus current database authorization**, never a
tenant supplied in a query parameter. For each record returned by the
repository within the requested UTC period, the business service now
prevalidates:

- `OrganizationId` must equal the authorized organization and
  `IssuedUtc` must belong to the requested inclusive-start,
  exclusive-end UTC period.
- `TimestampRecord.Validate()` must succeed. In particular, SHA-256
  computed over the original retained `ResponseDer` bytes must equal
  the stored `TokenSha256Hex`. These bytes may be a *signed but
  still unqualified* RFC3161 response. Comparing SHA-256 does **not**
  validate the original TSA service or its historical qualification.
- Every record ID must appear at most once **in that one page or
  complete returned ZIP batch**. Duplicate IDs would make
  `tokens/{id:N}.tsr` ZIP paths and manifest entries ambiguous, even
  if normal PostgreSQL PK/UNIQUE rules reject duplicates.

If any gate fails, the service **throws before returning any page
metadata or constructing any ZIP/manifest**. It does not return a
partial archive or silently skip an invalid item. The existing
tenant/period checks and `GET /stamps/{id}/receipt` consistency check
are preserved. Operators should investigate an unexpected failure as
a data-integrity incident rather than repeatedly downloading or
relabeling records `VerifiedQualifiedExternal`. The API may surface
an internal error for repository corruption; it must never serve the
unverified bytes as a valid downloadable result.

## Evidence and controlled deployment

The synchronous export still has its original **10,000 record cap**,
with an explicit too-large failure; this incremental improvement does
not provide complete arbitrary-period coverage, atomic snapshots
across pages, archive authentication, a protected manifest seal, an
immutable high-water witness, object-store WORM/legal holds, independent
re-verification of RFC3161 tokens, or compliant indefinite retention.
No database migration, cloud-specific service or new deployment setting
was introduced: on-prem OSS and Azure run the same validation code.

Test coverage:
`tests/backend/TemporalMark.Business.Tests/TimestampRegistryServiceTests.cs`
includes positive owner page/export, cross-tenant denials, corrupt
stored digest, modified DER, and duplicate record ID both in page and
export. TDD sequence: ADR 0074 `2d5ba2d` first, RED-only tests
`776ec20`, minimal production business fix `c220354`.

**Actual RED confirmed:** [GitHub Actions run 44281759576 attempt 1](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44281759576/attempts/1),
test-only main SHA `776ec202e7359bbb7ffe963440671df08eac8a9b`:
Domain 9/9; Business **232/236 passed, exactly 4 failed** in
`PageRejectsCorruptedStoredReceiptDigest`,
`PageRejectsTamperedDerEvenIfStoredDigestIsUnchanged`,
`PageRejectsDuplicateIdsBeforeReturningAnyMetadata`,
`ExportRejectsDuplicateReceiptIdsRatherThanProducingAmbiguousZipPaths`.
Frontend/terraform succeeded, Docker skipped after backend RED.
**GREEN must be separately proven** from the exact final
docs-inclusive `main` SHA with all four original jobs and actual
logs. Don't infer the fix passed simply because it landed.

## Legal/security stop line

ADR 0004 makes clear that a PostgreSQL registry and a zip file are
**not independently immutable evidence**. An attacker who can change
both `ResponseDer` and `TokenSha256Hex` can still create a
self-consistent forgery. Independent signed manifests and immutable
witnesses, WORM retention, trusted timestamp provenance, historical EU
Trusted List service status, authorized legal export completeness
proof and CAB/AgID qualification remain **OPEN #17/#15/#13**. All
unqualified pilot receipts remain `Unverified`. The WebAuthn
registrar V015/V016 stop-line is unchanged.

## Synchronous period ZIP memory budget (#106, ADR 0075)

The authenticated `GET /api/v1/stamps/export` still creates one ZIP
in memory, so row count alone does not limit its source DER size.
Before any ZIP/manifest allocation, the shared business service now
requires **each exported raw `ResponseDer` to be at most 1 MiB
(1,048,576 bytes)** and **the cumulative raw DER across that export
batch to be at most 64 MiB (67,108,864 bytes)**. The existing count
cap of 10,000 remains in force. These are *synchronous resource budgets*,
not legal DER size limits or certified long-term archive guarantees.
They match the current RFC3161 pilot's individual 1 MiB response
bound but also protect against legacy/oversized persisted database rows.

A limit violation raises the existing `ExportTooLargeException`,
translated by the API to **HTTP 413** with generic text asking the
tenant administrator to select a smaller interval. No partial ZIP,
manifest or valid receipt is returned. The byte-budget check runs
**before** computing every stored DER's SHA-256 and before allocating
the ZIP; the existing tenant, period, record hash and duplicate-ID
checks still run before any file is returned. The size gate does not
authenticate certificates, prove a timestamp qualified or implicitly
retry a TSA POST.

Test coverage in
`tests/backend/TemporalMark.Business.Tests/TimestampRegistryServiceTests.cs`
includes a **1 MiB +1** oversized stored receipt with matching SHA-256,
65 distinct 1 MiB receipts (65 MiB total, matching SHA-256) with one
reused test buffer, and a successful **exactly 1 MiB** receipt that
round-trips through the ZIP. The TDD sequence was
[ADR 0075](../adr/0075-synchronous-evidence-zip-byte-budget.md)
first, RED-first tests SHA `69d3254`, minimal service fix SHA
`ef36b34`. RED/GREEN runner outcomes must be checked on the actual
respective GitHub commits; the commits alone are not proof.

**Residual capacity risk:** `NpgsqlDataReader` and `ForExportAsync`
already materialize the rows before the business guard; this change
does **not** cap PostgreSQL response memory, concurrent exports,
ZIP output size, compression ratios or client download volume. For
arbitrarily large periods the still-open #17 requires reviewed,
audited streaming/asynchronous exports, bounded paging and snapshot
proof, signed manifests and immutable storage/object lock. The local
hash is **not** a separately signed WORM witness; historical legal
QTSP trust and CAB qualification remain #15/#13. All pilot evidence
remains `Unverified`; V015/V016 registrar interlock unchanged.


## Pilot-only read gate for unsupported qualification and incident labels (#156)

**The current issuer always persists `TimestampValidationState.Unverified`**. The schema V001 contains enum capacity for future independently verified statuses, but no production-ready qualified-service verification, historical trusted-list status or independent incident adjudication exists. A tenant-authorized row with matching DER/SHA256 and valid period can still be wrong if its `validation_state` is changed to `VerifiedNonQualified`, `VerifiedQualifiedExternal`, `VerifiedQualifiedOwn` or `AffectedByIncident`. Local SHA256 checks do not validate those business/legal assertions. [ADR 0121](../adr/0121-pilot-registry-unsupported-validation-state-read-gate.md) / [#156](https://github.com/KeyserDSoze/TemporalMark/issues/156) now require **exact `Unverified`** in the registry service on **every** pilot read that delivers evidence or status: paginated list, document-SHA256 search **including its lookahead row**, direct receipt download, and synchronous period ZIP. This reuses the existing common record-integrity helper and a direct download guard, after DER hash verification, and fails **before returning content** with a generic integrity exception. The application does not rewrite database states, silently label them Unverified, block future schema additions or assert any actual malicious input was observed.

[real .NET Business TDD RED 44970125295](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44970125295) on tests-only [`b1dc2e9`](https://github.com/KeyserDSoze/TemporalMark/commit/b1dc2e9d75ff0e3d2da77f36597c0f770f1a261a) proved **16 expected missing-denial failures and 264 existing Business passes**, with real intact, tenant-owned TSR/SHA256, all four stored state cases x four read surfaces; existing Unverified positive responses still pass. If this gate trips on actual data, **investigate database integrity and qualification provenance under governed incident processes**, do not patch SQL state to hide the warning. A future authorized `AffectedByIncident` or cryptographically verified status requires independent adjudication and ADR/TDD. Signed custody, qualified issuers, WORM and full-period completeness remain open #17/#15/#13/#64.


## Pilot synchronous export v1 serialized-manifest and ZIP byte caps (#166 / ADR 0124)

The previous synchronous export already bounded count (10,000), single raw DER (1 MiB) and total raw DER (64 MiB), but **not the uncompressed JSON manifest**. An otherwise valid tenant/UTC/DER/SHA/Unverified row with a long `EvidenceReference` or many individually modest strings could produce a small compressed ZIP whose `manifest.json` expanded beyond **8 MiB** and was then **rejected by TemporalMark's own offline v1 checker**. C# character count is not a safe estimate: JSON may escape Unicode, expanding the emitted UTF-8 JSON bytes.

[ADR 0124](../adr/0124-bounded-v1-manifest-and-zip-export-output.md)/[#166](https://github.com/KeyserDSoze/TemporalMark/issues/166) make the .NET export serialize the exact v1 manifest **once to an 8 MiB limited memory stream before creating the ZIP**. Synchronous/asynchronous writes are bounded on the emitted byte count; the same serialized bytes become `manifest.json`. Beyond this limit the service raises generic `ExportTooLargeException` (existing HTTP **413**, split period), no ZIP and no sensitive metadata error text. After constructing a valid archive, the service also prevents returning any physical ZIP beyond **80 MiB**, matching the offline verifier's outer limit. Existing DER/record-count, tenant, date, unique-ID and pilot-only Unverified guards remain, with identical on-prem/Azure code.

Actual [TDD xUnit RED 45052741202](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45052741202/attempts/1) on tests-only [`bdc24a8`](https://github.com/KeyserDSoze/TemporalMark/commit/bdc24a883660e0e9ef8112dfbcfc9b8d752d8eb5): **3 missing-denial failures / 281 passes**, verified legitimate DER+hash/tenant rows, while a 7 MiB accepted manifest test passed. Implementation after RED [`adb6725`](https://github.com/KeyserDSoze/TemporalMark/commit/adb6725dfc49cea559ae1bd34f7a490b4440dd29), [`7d7c76a`](https://github.com/KeyserDSoze/TemporalMark/commit/7d7c76a0899ee594d8f9c72ec6549401313ed088). Exact final docs-inclusive GREEN must be separately demonstrated. This does **not** bound PostgreSQL source-row materialization, concurrent export memory, arbitrary-period completeness, signed manifests, actual legal WORM storage, trusted RFC3161/QTSP/eIDAS status or GDPR retention; parent #17/#15/#13 remain OPEN.


## Exact real producer-to-offline v1 verifier CI gate (#167)

The two-tenant disposable live API smoke uses a signed Keycloak JWT and PG17 records to obtain actual in-memory ZIPs exported by .NET; it already checked manifest tenant and TSR equality, but previously trusted permissive `zipfile` parsing. [ADR 0125](../adr/0125-real-api-v1-offline-verifier-ci-bridge.md) / [#167](https://github.com/KeyserDSoze/TemporalMark/issues/167) add an independent **pre-parse** strict offline v1 `verify_archive` call on the same response bytes, for real A, B and spoofed-header/query requests, ensuring no regression to accepted prefixes/trailers, internal ZIP gaps, inconsistent local/central fields or unsupported current-v1 metadata in these CI samples. The count is cross-checked against the parsed manifest; no ZIP is persisted or printed. Redacted error if rejected. Real test-only [RED 45053967169](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45053967169/attempts/1) found the missing checker (1 negative failure, 1 positive pass); source [`e80fa29`](https://github.com/KeyserDSoze/TemporalMark/commit/e80fa2944177aae5bb5d8a493595363f90253f09) followed that RED. This is **CI local structure+SHA256 compatibility**, not a trusted signed/witnessed period export or lawful retention. Parent #17/#15/#13 remain OPEN.


## Reject unbounded/unordered registry and exact-imprint batches (#168 / ADR 0126)

The real PostgreSQL provider sends `ORDER BY issued_utc,id` with bounded `LIMIT`, but the business read boundary previously accepted an oversized `PageAsync` or descending `IssuedUtc/Id` record order, even with perfectly intact, authorized, pilot-only DER/SHA256. A faulty repository adapter could therefore return more metadata than requested or present unstable page navigation. The new [ADR 0126](../adr/0126-fail-closed-registry-page-and-imprint-search-order.md)/[#168](https://github.com/KeyserDSoze/TemporalMark/issues/168) guard requires **page count <= requested limit** and **strictly increasing (UTC issued timestamp, canonical UUID)** for the complete returned page and exact-imprint search batch, including the `limit+1` extra result used to compute `hasMore`. This is checked after tenant/period, SHA256 token, `Unverified`, unique-ID checks, and before serving any result. The existing 1..200 page and 1..50 search bounds, server-bound tenant and audit/rate-limit controls are untouched. No SQL, migration, REST, auth or cloud divergence.

Real tests-only [RED 45056357292](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45056357292/attempts/1): **290 Business, 5 genuine missing-denial failures / 285 passes**, including passing positive same-timestamp sorted IDs; after RED only implemented [`216ae1b`](https://github.com/KeyserDSoze/TemporalMark/commit/216ae1b1257bbea7d2049dad3d4dd9b93800d3e8). Full docs-inclusive CI GREEN must be independently checked. This does NOT make offset pagination a transactional snapshot, ensure complete period export, independently seal evidence, provide WORM/retention or verify historical qualified QTSP/eIDAS status.
