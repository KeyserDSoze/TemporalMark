# ADR 0054 — Fail-closed external TSA endpoint URI and explicit development loopback

Status: Accepted as pilot transport-hardening decision (2026-11-16). Issue [#85](https://github.com/KeyserDSoze/TemporalMark/issues/85), child of open [#15](https://github.com/KeyserDSoze/TemporalMark/issues/15). **No legal QTSP qualification or complete SSRF defense.**

## Reviewed implementation and boundaries

Reviewed ADR [0002](0002-qualified-vs-delegated-timestamping.md), [0052](0052-external-tsa-http-no-redirect-policy.md), [0053](0053-rfc3161-strict-http-response-envelope.md), [TSA transport runbook](../docs/TSA_HTTP_TRANSPORT.md), [threat model](../docs/THREAT_MODEL.md), and API/provider code. The ASP.NET API currently allows HTTP loopback only when `IHostEnvironment.IsDevelopment`, but reusable `ExternalRfc3161TimestampProvider.RequestAsync` independently accepts **HTTP loopback regardless of environment**. Its check does not guard HTTPS loopback, IP literals, URI userinfo or fragments, although the URL comes from deployment configuration and not a tenant.

## Decision

- A dedicated `ExternalRfc3161EndpointPolicy.Validate(Uri endpoint, bool allowDevelopmentLoopback)` is the single runtime pre-send policy in the provider. Reject relative/non-absolute URIs, non-HTTPS protocols, `UserInfo` and `Fragment` regardless of development setting. Do not copy a URL with embedded authentication credentials to outbound request/logging.
- Production/default mode requires HTTPS and **a DNS host name** (`UriHostNameType.Dns`), and rejects `Uri.IsLoopback` even over HTTPS, as well as IPv4/IPv6 literals. Public IP literal TSAs are excluded by this deliberately conservative operational profile: operators must configure a DNS name with valid HTTPS peer identity. The policy does **not** establish that a DNS name resolves to a publicly routable IP or a qualified TSA.
- Explicit test/development mode `allowDevelopmentLoopback:true` allows a **loopback** HTTP or HTTPS endpoint; its intended purpose is disposable local integration only. HTTPS DNS provider endpoints remain allowed regardless. Other IP literals and HTTP remote endpoints remain rejected. Only `builder.Environment.IsDevelopment()` supplies this flag in API DI; no HTTP parameter, tenant setting, query, or JWT may override it. The provider's default is `false` even if constructed outside the API.
- Validate **before any outbound HTTP send or response parsing** and raise a generic `TimestampProviderUnavailableException`. No DNS lookup, network connect or credential logging is performed by the policy. Server-owned URL remains configured once at injection; existing no-redirect/no-cookie and bounded/strict MIME response checks remain intact.
- TDD: commit ADR, then failing real-provider spy-handler tests on main, observe CI RED. Implement policy and DI integration; update runbook, threat model and roadmap. Close #85 only after final exact-main four-job GREEN.

## Residual high-priority gaps

This static syntax gate is only defense-in-depth. DNS rebinding, private-address DNS answers, outbound proxy, HTTP CONNECT, cluster ingress and Azure metadata service abuse remain possible without verified **connection-time** destination checks, egress network policies and approved DNS/host inventory. On-prem and Azure must separately block private/link-local/metadata destinations and enforce an audited TSA allowlist, without a second unchecked DNS resolve. The external timestamp remains `Unverified`; CMS, EKU, certificate path/revocation, historical EU Trusted Lists, long-term WORM and qualified legal status remain #15/#17/#13.

## Sources

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [.NET Uri class / IsLoopback / HostNameType / UserInfo / Fragment](https://learn.microsoft.com/en-us/dotnet/api/system.uri?view=net-10.0)
