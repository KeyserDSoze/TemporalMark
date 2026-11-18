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

## Amendment — cancellation provenance must follow the caller token (2026-11-18)

The #99 transport boundary also needs to distinguish **exception subclass** from
**who actually cancelled the operation**. `OperationCanceledException` is the base
class of `TaskCanceledException`; a response stream or handler can throw the base
class when its internal timeout/abort happens without the caller's
`CancellationToken` being signalled. A catch for only `TaskCanceledException`
misses that failure and can result in an unhandled API 500. Conversely,
swallowing every `OperationCanceledException` would erase the caller's
intentional cancellation.

Update the existing, narrow exception boundary to catch
`OperationCanceledException` **only when the original caller token's
`IsCancellationRequested` is false**. Return the same generic
`TimestampProviderUnavailableException("External TSA request timed out.")`;
do not include the raw exception message, retry automatically, persist
a partial response or claim remote issuance did not happen. If the caller
token is cancelled, propagate cancellation unchanged.

TDD order for this amendment: update this ADR first; append RED-first
`HttpMessageHandler` and `Stream` tests for base-class cancellation on
send, stream acquisition and after a partial body, plus cancellation during
stream read by a real caller token; then change the catch minimally, update
runbook/threat/roadmap/issue and require exact-final SHA 4/4 GitHub CI.
The prior I/O tests and all legal, tenant, and WebAuthn gates remain intact.

References: [.NET OperationCanceledException](https://learn.microsoft.com/en-us/dotnet/api/system.operationcanceledexception?view=net-10.0);
[.NET TaskCanceledException](https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.taskcanceledexception?view=net-10.0).

## Amendment — premature disposal by the response stream (2026-11-18)

A broken or prematurely disposed `HttpContent` body stream may throw
`ObjectDisposedException` from `Stream.ReadAsync`, and even from
`HttpContent.ReadAsStreamAsync`. `ObjectDisposedException` derives from
`InvalidOperationException`, **not** `IOException`; neither the accepted
`catch(IOException)` nor the non-caller `OperationCanceledException` handler
normalizes it. An externally supplied HTTP stream cannot be allowed to turn
an unknown, incomplete RFC3161 response into a raw unhandled API 500.

Narrowly normalize only **`ObjectDisposedException`**, within the same
existing `RequestAsync` transport/body boundary, to the existing generic
`TimestampProviderUnavailableException("Unable to read the configured external TSA response.")`.
No broad `InvalidOperationException` or general `Exception` catch, no retry,
no partial DER persistence, no change to semantic/PKIX/signature error paths.
Keep genuine cancellation separate: the catch filter must apply **only when
the original caller cancellation token has not been signalled**; otherwise
preserve the original exception rather than incorrectly claiming a TSA outage.

TDD order: ADR amendment first; RED-first in-memory `HttpContent` tests
for stream acquisition `ObjectDisposedException` and partial response then
`ObjectDisposedException`, with raw diagnostic sentinel assertions and
the existing caller-cancellation/IO/malformed-DER checks intact; minimal
provider `catch(ObjectDisposedException) when (!cancellationToken.IsCancellationRequested)`;
update TSA operator runbook, threat model, roadmap and issue #99. Close only
after exact final documentation-inclusive main SHA 4/4 CI. No qualified trust.

Reference: [ObjectDisposedException hierarchy](https://learn.microsoft.com/en-us/dotnet/api/system.objectdisposedexception?view=net-10.0).
