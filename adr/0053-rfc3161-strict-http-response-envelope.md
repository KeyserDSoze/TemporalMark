# ADR 0053 — Strict RFC 3161 HTTP response envelope before DER parsing

Status: Accepted for limited delegated-connector pilot hardening (2026-11-16). Child [#84](https://github.com/KeyserDSoze/TemporalMark/issues/84) of [#15](https://github.com/KeyserDSoze/TemporalMark/issues/15). **NOT QUALIFIED**.

## Sources and reviewed baseline

Reviewed [ADR 0002](0002-qualified-vs-delegated-timestamping.md), [ADR 0052](0052-external-tsa-http-no-redirect-policy.md), [external TSA transport runbook](../docs/TSA_HTTP_TRANSPORT.md), [threat model](../docs/THREAT_MODEL.md), the real `ExternalRfc3161TimestampProvider.RequestAsync`, existing `external-tsa` dependency-injection wiring and `ExternalRfc3161TransportPolicyTests`. RFC 3161 §3.4 defines the HTTP response content type **`application/timestamp-reply`**. Its *original* final paragraph mistakenly mentions `application/timestamp-response`; **verified erratum EID 1879** corrects this to `application/timestamp-reply`. Do not accept the erroneous alternative.

The pilot already sends a DER RFC 3161 request with `application/timestamp-query`, requests the correct Accept MIME, disallows implicit HTTP redirects, bounds the response to 1 MiB, checks nonce/imprint and a CMS signer signature using .NET 10. But its current broad HTTP success test `IsSuccessStatusCode` accepts 202/206 and its parser reads the body before validating response MIME.

## Decision and TDD sequence

1. **Strict local transport profile:** require exactly `200 OK` as the final HTTP status. This is a conservative **TemporalMark operational policy**, not a claim that RFC 3161 itself explicitly mandates 200 rather than every other successful HTTP status. Reject 201, 202, 204, 206, 3xx and any failure; there is no polling/partial-result feature in this pilot.
2. Require **`response.Content.Headers.ContentType.MediaType`** to equal `application/timestamp-reply` using `OrdinalIgnoreCase`. Missing, malformed or different MIME including `application/timestamp-response`, `application/json` or `application/octet-stream` is rejected **before reading the stream or parsing ASN.1**. Optional ordinary MIME parameters such as `name` are compatible; a valid media type alone can never validate cryptographic evidence.
3. Return a generic `TimestampProviderResponseException` for status and media-type mismatches (no body, endpoint credentials or digest included in error). Maintain all existing no-redirect/no-cookie, body size, timeout and pinning defenses. Never persist a failed or ambiguous response.
4. **TDD:** commit this ADR first; commit failing .NET 10 tests on `main`, observe targeted RED in Actions; apply provider-only GREEN change; update roadmap, threat model, runbook. Close #84 only after all four GitHub CI jobs succeed on **exact final main SHA**.

## Residual risk and release gates

Content-Type is an untrusted network header, not proof of an RFC 3161 response. Complete DER/CMS validation and negative corpus, TSA certificate EKU/chain/history/revocation, qualified-service status from historical EU Trusted Lists, provider interoperability and signed immutable evidence are still missing under #15/#17/#13. A rogue configured provider, DNS/proxy egress and platform operators remain external trust boundaries. All pilot stamps remain **`Unverified`** and cannot be labelled qualified.

## Authoritative references

- [RFC 3161 §3.4 — HTTP transfer](https://www.rfc-editor.org/rfc/rfc3161#section-3.4)
- [RFC Editor verified erratum 1879](https://www.rfc-editor.org/errata/eid1879)
- [.NET 10 Rfc3161TimestampRequest](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamprequest?view=windowsdesktop-10.0)
