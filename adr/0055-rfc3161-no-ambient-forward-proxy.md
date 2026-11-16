# ADR 0055 — Dedicated RFC 3161 TSA HTTP transport must bypass ambient forward proxies

Status: Accepted for limited pilot transport hardening (2026-11-16); child [#86](https://github.com/KeyserDSoze/TemporalMark/issues/86) of open [#15](https://github.com/KeyserDSoze/TemporalMark/issues/15). **Not qualified; not a complete egress or SSRF solution.**

## Reviewed baseline and sources

Reviewed [ADR 0002](0002-qualified-vs-delegated-timestamping.md), [ADR 0052](0052-external-tsa-http-no-redirect-policy.md), [ADR 0053](0053-rfc3161-strict-http-response-envelope.md), [ADR 0054](0054-rfc3161-endpoint-uri-development-loopback.md), [threat model](../docs/THREAT_MODEL.md), [transport runbook](../docs/TSA_HTTP_TRANSPORT.md), `ExternalRfc3161TransportPolicy.CreateHandler` and the `external-tsa` named client registration in `TemporalMark.Api/Program.cs`. The named handler already disables redirects and cookies; the provider refuses non-HTTPS, loopback/IP, userinfo/fragment and wrong RFC 3161 response envelopes, and caps response bytes/time.

Per official [.NET 10 `HttpClientHandler.UseProxy` documentation](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.useproxy?view=net-10.0), its default is **true**. When a handler has no explicit `Proxy` object, [`HttpClient.DefaultProxy`](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclient.defaultproxy?view=net-10.0) can use ambient OS, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` settings. Therefore a reviewed TSA hostname is not sufficient to guarantee that an imprint-bearing RFC 3161 HTTP request goes directly to that peer; a host-level proxy may be an uncontrolled secondary transport destination.

## Decision

1. Set **`UseProxy = false`** explicitly in `ExternalRfc3161TransportPolicy.CreateHandler`, installed only on named `external-tsa` `HttpClient`. Do **not** modify application-wide or IdP/OIDC clients. Preserve `AllowAutoRedirect=false`, `UseCookies=false`, the 20-second timeout and the provider's signed CMS/nonce/imprint checks.
2. Keep `Proxy`, `DefaultProxyCredentials`, `Credentials` absent; keep `UseDefaultCredentials=false`, `PreAuthenticate=false` and `AutomaticDecompression=None`. Negative unit regression tests inspect the *actual* primary handler settings; they do not mutate environment variables or create a misleading simulated network/proxy assertion. Handler instances are fresh and isolated.
3. Configure **direct** network egress to the operator-approved HTTPS DNS TSA origin. If a deployment requires a corporate forward proxy, this pilot **fails connectivity** rather than falling back to ambient proxy variables. A supported approved-proxy feature needs a separate ADR, explicit operator configuration, proxy identity controls, controlled credentials, and real integration tests. Both on-prem and Azure must retain feature parity with direct egress.
4. TDD: commit this ADR, commit RED tests on `main`, observe GitHub backend failure; then one transport policy change and docs. Close #86 **only** after exact final-main SHA successful `backend`, `frontend`, `docker-smoke`, `terraform`.

## Unresolved threats

This only blocks **`HttpClientHandler` forward proxy selection** and its ambient OS/env source; it cannot eliminate transparent L3/L4 proxies, DNS responses yielding private IPs, DNS rebinding, privileged service-mesh interception, malicious network appliances, or ensure TLS peer/TSA qualification. Must deploy independently audited DNS/connection-time restrictions, egress firewall and CA policy. Neither a valid MIME/DER nor a cryptographically signed response establishes historical EU Trusted List qualification, certificate path/revocation or WORM custody. `Unverified` remains the pilot record status, with QTSP #15, WORM #17, legal #13 open.

## References

- [Microsoft .NET 10 HttpClientHandler.UseProxy](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.useproxy?view=net-10.0)
- [Microsoft .NET 10 HttpClient.DefaultProxy](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclient.defaultproxy?view=net-10.0)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
