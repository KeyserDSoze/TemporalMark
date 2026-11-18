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
