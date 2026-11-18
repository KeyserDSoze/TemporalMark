# ADR 0073 — Distinguish upstream TSA HTTP overload/timeouts without retry

Status: Accepted for **UNQUALIFIED delegated RFC3161 pilot only** (2026-11-18). Child [#104](https://github.com/KeyserDSoze/TemporalMark/issues/104) of open #15.

## Baseline and authoritative behavior

Reviewed ADR [0002](0002-qualified-vs-delegated-timestamping.md), [0053](0053-rfc3161-strict-http-response-envelope.md), [0068](0068-rfc3161-response-stream-io-fail-closed.md), [0072](0072-canonical-sha256-base64-issuance-ingress.md), `ExternalRfc3161TimestampProvider.RequestAsync` and `ExternalRfc3161ResponseEnvelopeTests`, the authenticated `/api/v1/stamps/issue` route's exception mapping, and `docs/TSA_HTTP_TRANSPORT.md`, `docs/THREAT_MODEL.md` and `docs/ROADMAP.md`. All non-200 upstream statuses currently throw `TimestampProviderResponseException` (API **502**) even for common upstream capacity/timeout signals. This confuses **the external TSA's inability to serve a request** with an **invalid 200 OK DER/CMS response**.

[RFC 9110 §15.5.9](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.9) describes HTTP 408; [§15.6.4](https://www.rfc-editor.org/rfc/rfc9110#section-15.6.4) describes HTTP 503 temporary unavailability, [§15.6.5](https://www.rfc-editor.org/rfc/rfc9110#section-15.6.5) describes 504 gateway timeout; [RFC 6585 §4](https://www.rfc-editor.org/rfc/rfc6585#section-4) defines HTTP 429 Too Many Requests. A 429/503 can include an untrusted `Retry-After`. None of these **proves** that the remote TSA did not process, issue or bill an imprint before the client received its error response.

## Decision

1. Under the existing *strict 200 OK only* pilot HTTP envelope, special-case only these upstream statuses: `408 RequestTimeout`, `429 TooManyRequests`, `503 ServiceUnavailable`, `504 GatewayTimeout`. Before considering MIME or reading **any** content, map them to a fixed `TimestampProviderUnavailableException("External TSA is temporarily unavailable.")`, causing the authenticated API's existing **503**. Do not echo status reason phrases, `Retry-After`, response URI, raw body, private imprint or diagnostic details.
2. Leave all other statuses—including 400/401/403/404, 500, 502, 3xx, and 201/202/204/206—on the existing generic `TimestampProviderResponseException("TSA returned an unexpected HTTP status.")` -> API **502** path. Do not weaken the strict `application/timestamp-reply` check when HTTP is exactly 200. A status is **untrusted** transport metadata, never a cryptographic token.
3. **Never retry automatically** or forward upstream `Retry-After` to callers. Retrying a TSA POST without confirmed issuance reconciliation/idempotency can produce duplicate timestamps or charge the tenant twice. Real rate limiting, quotas, reconciliation and operator-controlled backoff belong to a separately reviewed #15 increment, not this status-classification boundary.
4. TDD: commit this ADR first, RED-first xUnit using actual `ExternalRfc3161TimestampProvider` plus throw-on-read `HttpContent` for all four unavailable statuses and negative controls; implement minimal provider-only classification; update operator runbook/threat/roadmap; observe actual RED and exact final documentation-inclusive 4/4 GitHub CI before closing #104.
5. The implementation is shared by on-prem and Azure; no new database, tenant config, API route, WebAuthn/registrar privilege, trust certificate or qualified QTSP claim. All evidence remains `Unverified`. Parents #15, #17, #13 and V015/V016 stop-line remain OPEN.

## Limits

The HTTP status can be forged by a compromised upstream. The default `HttpClient` may time out or disconnect without a status; that is already the fail-closed #99 transport path. No promise of retry safety, recovery time, external service availability, qualified trust, UTC(k), EUTL historical status or WORM storage is created.
