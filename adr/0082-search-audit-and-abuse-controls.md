# ADR 0082 — Privacy-minimized tenant imprint-search audit and abuse controls

- Status: **Proposed; implementation gated on RED-first tests and security/privacy review**
- Date: 2026-11-18
- Tracking: #113 (child of #17; follow-up to completed #112)

## Context

The pilot offers a tenant-admin-only `POST /api/v1/stamps/search` for exact SHA-256 document imprints. Its read-only tenant scoping and bounded pagination do **not** constitute an audit trail of searches. Receipt-download audit events cover a different action. Search queries may be sensitive even when represented as a digest: a document imprint can be linkable to a known document, and zero/nonzero results can reveal membership.

Existing tenant audit persistence and authorization must be inspected before choosing an implementation. Review ADR 0004, 0079, 0080 and 0081, the current audit schema, service, API middleware, and on-prem/Azure deployment settings. This ADR does not certify their behavior.

## Decision proposed for #113

1. Every successful authorized search that could reveal matching data must append a **dedicated tenant-scoped search audit event** before any matching result is returned. If audit persistence fails, deny the search (fail closed). Do not record events for unauthenticated requests in the tenant audit ledger under a fabricated tenant identity; record rejected attempts only in separately controlled security telemetry where justified.
2. The tenant audit payload must not contain the raw searched SHA-256 imprint, request body, matching document identifiers, or full response. Prefer action name, authenticated tenant/principal reference, UTC time, request/correlation ID, outcome category and minimal policy version. Do **not** store a deterministic plain SHA-256 of the searched imprint: it enables dictionary correlation. Any tenant-keyed HMAC proposal requires independent key custody, rotation and DPIA review before adoption; default is **no query fingerprint**.
3. Search-result counts and even match/nonmatch flags are excluded from audit by default until necessity and retention are explicitly approved. Do not imply this audit is immutable, independently sealed, WORM, or qualified evidence.
4. Introduce bounded per-tenant **and** per-principal search-abuse controls, with deterministic HTTP 429 and a documented Retry-After policy. Evaluate concurrent requests, expiration, principal rotation, tenant-wide flooding, client IP spoofing, proxy trust and service restarts. A process-local limiter alone does not establish distributed enforcement; select an OSS-compatible distributed design and Azure parity before enabling production.
5. Never log the POST body or imprint in API, reverse proxy, tracing, exception, telemetry, rate-limit keys or access logs. Preserve existing role and tenant checks, validation and pagination; neither a caller-supplied tenant ID nor headers may override the authenticated scope.
6. Preserve strict non-claims boundaries: the search and its audit do not independently validate RFC3161/CMS, historical EU Trusted Lists, signed custody, completeness of period exports or qualified timestamp status. V015/V016 registrar freeze remains unchanged.

## Test-driven acceptance sequence

- **RED:** xUnit tests for action-specific audit append, tenant/principal scope, no raw imprint/count in payload, audit-store failure causing denial, and no audit mutation for unauthorized/malformed requests.
- **RED:** real signed-Keycloak/two-tenant PostgreSQL HTTP tests for independent tenant isolation, role restrictions, search audit read-back, body/header/query spoof attempts, and persistence outage. Ensure no match data leaks on audit failure.
- **RED:** adversarial rate-limit tests for distinct principals in one tenant, tenant-wide aggregate, parallel requests, threshold, reset/expiry, 429/Retry-After, trusted proxy headers, and deployment-restart behavior.
- **GREEN:** implement the smallest service, schema/migration and infrastructure changes that pass the tests, retaining on-prem OSS/Azure behavior parity.
- **VERIFY:** review redaction in real proxy/application traces; update operator runbooks, threat model, privacy retention/DPIA decisions and roadmap. Require exact documentation-inclusive final main SHA with backend, frontend, docker-smoke and terraform GitHub CI success before closing #113.

## Open security decisions before implementation

- Audit retention period, access restrictions, data-subject handling and lawful basis need explicit privacy/legal review; the platform's indefinite evidence-retention policy must not automatically be applied to search-behavior telemetry.
- Select distributed rate-limit storage/coordination with failure semantics and disaster recovery; no mandatory Azure-only component.
- Confirm audit event schema evolution, tenant access rights, ordering/atomicity and safe error mapping against current PostgreSQL implementation.

## Consequences

The pilot can improve detection and response to search enumeration without turning imprints into a new searchable telemetry dataset. Search availability becomes dependent on audit persistence; this is intentional for sensitive successful lookups. Audit integrity and independently signed custody remain tracked by #17, not delivered by this ADR.
