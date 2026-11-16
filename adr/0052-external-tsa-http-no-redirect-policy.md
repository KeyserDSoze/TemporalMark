# ADR 0052 — External RFC 3161 TSA HTTP transport must never follow redirects

Status: Accepted for limited pilot transport hardening (2026-11-16). Issue [#83](https://github.com/KeyserDSoze/TemporalMark/issues/83), child of [#15](https://github.com/KeyserDSoze/TemporalMark/issues/15). **No qualification or complete SSRF protection is claimed.**

## Reviewed baseline

Reviewed [ADR 0002](0002-qualified-vs-delegated-timestamping.md), [threat model](../docs/THREAT_MODEL.md), `ExternalRfc3161TimestampProvider.RequestAsync`, the `external-tsa` named `HttpClient` registration in `TemporalMark.Api/Program.cs`, and the existing business stamping tests. The API uses a server-owned configured absolute TSA URL, enforces HTTPS outside explicit development loopback, and caps response length and time. Its named `HttpClient` currently does **not** disable automatic redirects.

Microsoft documents `HttpClientHandler.AllowAutoRedirect` as **true by default** and states that 300–399 responses are exposed to the caller when disabled. RFC 9110 section 15.4.8/15.4.9 explicitly preserves POST method on 307/308 redirects. An untrusted or compromised TSA endpoint can therefore move a signed timestamp *request* (including the digest) to an arbitrary second host if implicit redirect handling remains enabled. HTTPS-to-HTTP downgrade protection does not remove same-scheme SSRF or authority confusion.

## Decision

1. One dedicated `ExternalRfc3161TransportPolicy.CreateHandler()` returns a fresh `HttpClientHandler` with `AllowAutoRedirect=false` and `UseCookies=false`. The API must install it with `ConfigurePrimaryHttpMessageHandler` for **only** the `external-tsa` named client, maintaining the existing 20-second timeout.
2. The provider's existing `!response.IsSuccessStatusCode` check rejects any 3xx response **without following Location**, parsing a token or persisting evidence. Tests cover every common 301/302/303/307/308 case and ensure the handler policy is not accidentally reverted.
3. The configured server-only HTTPS TSA endpoint remains immutable for each request; a tenant cannot override it. No automatic discovery, browser-controlled `Location`, HTTP cookies or userinfo from redirects are allowed. A provider relocation requires a reviewed operational configuration change.
4. TDD order: commit this ADR, commit failing tests on `main` first, then commit the handler, DI wiring and operational documentation. Run existing four CI jobs against the final exact `main` SHA. Do not close #83 before observing GREEN.

## Residual risks

This does **not** pin DNS/IP/TLS peer identity, forbid deployment-provided HTTP proxies, guarantee egress firewall policy, or address DNS rebinding and misconfigured endpoint hostnames. Both Azure and on-prem must independently restrict outbound network access to approved TSA destinations and audit configuration changes. Production qualification also requires signed RFC3161/CMS verification, historical EU Trusted List/service status, signer certificate path and revocation evidence, expiry and policy checks. `Unverified` remains the only persisted state of this pilot connector.

## References

- [Microsoft .NET HttpClientHandler.AllowAutoRedirect](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.allowautoredirect?view=net-10.0)
- [IETF RFC 9110 §15.4.8–9, HTTP 307/308 redirect semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.8)
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161)
