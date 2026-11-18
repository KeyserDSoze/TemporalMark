# ADR 0068 — Fail-closed external TSA response-stream I/O boundary

Status: Accepted for the **unqualified delegated pilot**, 2026-11-18; focused child [#99](https://github.com/KeyserDSoze/TemporalMark/issues/99) of open #15.

## Reviewed context

Consulted ADR 0002 and 0052–0067, `ExternalRfc3161TimestampProvider.RequestAsync`, `ExternalRfc3161TransportPolicy`, `ExternalRfc3161ResponseEnvelopeTests`, `TimestampIssueService`, the authenticated API `/stamps/issue` exception mapping, and the current `docs/TSA_HTTP_TRANSPORT.md`, `docs/THREAT_MODEL.md`, `docs/ROADMAP.md`. The delegated client enforces a strict pre-send trust configuration, a 200/application-timestamp-reply envelope, and a bounded 1 MiB DER response. With `HttpCompletionOption.ResponseHeadersRead` it calls `HttpContent.ReadAsStreamAsync` and then repeatedly `Stream.ReadAsync`. Existing outer catches normalize `HttpRequestException` and non-caller `TaskCanceledException`, but do not normalize **`IOException`** from stream acquisition or a partially delivered body. A raw exception can bypass the API's mapped 503/502 error paths.

.NET's [NetworkStream.ReadAsync](https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.networkstream.readasync?view=net-10.0) may report underlying socket failure as `IOException`; [HttpContent.ReadAsStreamAsync](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpcontent.readasstreamasync?view=net-10.0) can surface stream failures. Do not rely on an HTTP 200 alone: a response interrupted mid-DER is not a valid timestamp. Such failures are transport availability failures, **not** qualified trust/validation evidence.

## Decision

1. Add **RED-first** adversarial in-memory HttpMessageHandler/HttpContent/Stream fixtures for a correct HTTP envelope whose response-stream acquisition fails, whose body delivers a prefix and then fails, and a handler that throws an I/O exception. The provider must expose only a generic `TimestampProviderUnavailableException` and never raw low-level/internal exception text, nor return a `ProviderTimestamp`. Test that existing non-I/O, malformed DER remains a response error and that an explicit caller cancellation remains a cancellation.
2. Add a narrow `catch (IOException)` to the existing outer provider request boundary, mapping to `TimestampProviderUnavailableException("Unable to read the configured external TSA response.")`. No broad `catch(Exception)`: genuine cancellation, argument/configuration and cryptographic validation exceptions retain their distinct semantics. Do not change HTTP status/MIME/body limits, controlled egress, PKIX/CRL/accuracy gates or persistence.
3. Keep on-prem and Azure identical (same .NET provider, no new settings). No new HTTP endpoint, tenant input, SQL/WORM privileges or WebAuthn registrar activation. All receipts stay `Unverified`.
4. Update operator docs, threat model and roadmap; verify all four jobs on exact final docs-inclusive `main` HEAD before closing #99. #97/#98 are pending separate CI proof; parents #15/#17/#13 remain open.

## Residual risks

An interrupted HTTP response might have been issued remotely; this slice cannot prove delivery, remote TSA request idempotency or exact external resource consumption. It does **not** implement an issuance outbox, external provider retries, provider-specific rate limits, historical EU Trusted List qualification, independently observed UTC(k) time, WORM evidence, CAB/AgID approval or a legally qualified TemporalMark TSA. Never infer an issued timestamp from a partial HTTP stream.

## Primary references

- [Microsoft NetworkStream.ReadAsync](https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.networkstream.readasync?view=net-10.0)
- [Microsoft HttpContent.ReadAsStreamAsync](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpcontent.readasstreamasync?view=net-10.0)
- [ADR 0053 response HTTP envelope](0053-rfc3161-strict-http-response-envelope.md)
