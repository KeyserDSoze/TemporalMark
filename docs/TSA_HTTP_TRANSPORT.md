# External RFC 3161 TSA — fail-closed outbound HTTP transport (#83)

**Pilot only. NOT QUALIFIED.** ADR [0052](../adr/0052-external-tsa-http-no-redirect-policy.md) documents the security decision. Parent [#15](https://github.com/KeyserDSoze/TemporalMark/issues/15) stays open for RFC 3161/PKI and EU Trusted List verification.

## Deployment configuration

`TimestampProvider:Url` and `TimestampProvider:Id` are owned by the operator, not the tenant. The API requires an absolute HTTPS URL outside the explicit **development-only** localhost HTTP exception. The named `external-tsa` HttpClient retains a 20-second request timeout but installs `ExternalRfc3161TransportPolicy.CreateHandler()` as its primary handler.

The handler sets **`AllowAutoRedirect=false` and `UseCookies=false`**. All 301, 302, 303, 307 and 308 replies fail the provider's existing non-success HTTP status check; the client must not forward a POST with its message imprint/nonce to the `Location` supplied by the responder. A TSA URL migration requires a deployment-level change and approval, rather than silently honoring redirects or a tenant-supplied URL. The implementation and test apply to both the Azure and on-prem API deployments.

## Test/review evidence

TDD tests in `tests/backend/TemporalMark.Provisioner.Tests/ExternalRfc3161TransportPolicyTests.cs` assert the **real primary handler policy** and five negative redirect statuses on the provider path. Test with:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161TransportPolicyTests
```

Issue #83 closed after all four jobs passed on exact main SHA `c7c48bdebbc164785eac6bc73ee7c9678796553d`: [CI 43899567218](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43899567218). No real upstream TSA request is made by these unit tests.

## Not covered

This transport setting is not a comprehensive SSRF defense: network policy must separately restrict outbound destinations, DNS, proxies, private addresses and metadata services. A compromised configured TSA or egress proxy remains a threat. Do not infer trust or qualified legal status from a cryptographically signed token alone: signer revocation/history, certificate chain, qualified status at issuance time, policy, key and algorithm conformance, timestamp accuracy and WORM evidence are tracked in #15/#17/#13. Persisted pilot records remain `Unverified`.

## Normative and runtime references

- [Microsoft .NET 10 HttpClientHandler.AllowAutoRedirect](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.allowautoredirect?view=net-10.0)
- [RFC 9110 §15.4.8/15.4.9 HTTP redirect semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.8)
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161)

## Strict RFC 3161 HTTP response envelope (#84, ADR 0053)

A 2xx HTTP status by itself does **not** imply a complete timestamp reply. The provider requires **exactly 200 OK** (a conservative TemporalMark policy; not a separate RFC 3161 explicit status-code requirement) and the HTTP response MIME media type **`application/timestamp-reply`** before opening or parsing the body. Missing, wrong or the misprinted `application/timestamp-response` MIME are rejected without reading the body. The intended media type is specified in [RFC 3161 §3.4](https://www.rfc-editor.org/rfc/rfc3161#section-3.4) with correction in [verified erratum EID 1879](https://www.rfc-editor.org/rfc/inline-errata/rfc3161.html). Case-insensitive media-type spelling and ordinary optional parameters such as `name` remain valid. HTTP 201/202/204/206 have no polling/partial-response path in this pilot and are rejected.

Negative tests in `tests/backend/TemporalMark.Provisioner.Tests/ExternalRfc3161ResponseEnvelopeTests.cs` use the real provider and a throw-on-read body to prove rejection **before DER consumption**. The proper envelope reaches the existing DER/CMS parser, not a new acceptance shortcut:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161ResponseEnvelopeTests
```

RED proof: [CI 43902202323](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43902202323) failed 10 targeted cases on the test-first commit. #84 **closed** after exact final-main all-four-job [CI 43902761373](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43902761373), SHA `997fd035df7e102a024f001ed623767b1269cd71`. The response Content-Type is **untrusted metadata**; it cannot establish signature trust, revocation status, historical EU Trusted List qualification, UTC traceability or WORM integrity. The record continues to be `Unverified`. See [ADR 0053](../adr/0053-rfc3161-strict-http-response-envelope.md). Parent #15, preservation #17 and compliance #13 remain OPEN.

## Endpoint URI authority and explicit local test exception (#85; ADR 0054)

The reusable RFC 3161 client now applies `ExternalRfc3161EndpointPolicy.Validate` **before any network send**, even when constructed outside the API. Its secure default rejects non-absolute URIs, non-HTTPS, URI `userinfo` (embedded credentials), fragments, all direct IPv4/IPv6 address literals (including metadata IPs), and loopback/localhost even if HTTPS. Production TSA endpoints must use **operator-configured DNS host names with HTTPS**. Path and query parameters remain allowed for approved server configuration; never take them from users or tenant input.

Only the ASP.NET API's trusted `builder.Environment.IsDevelopment()` value can set `allowDevelopmentLoopback:true` in the provider. That flag allows **HTTP or HTTPS loopback** (localhost, 127.0.0.1, ::1) solely for disposable local development. It does **not** permit external HTTP, arbitrary private/direct-IP hosts, userinfo or fragments. The default for any independently instantiated provider is always `false`.

Unit regressions (`tests/backend/TemporalMark.Provisioner.Tests/ExternalRfc3161EndpointPolicyTests.cs`) use the **real provider and a counting fake HTTP handler** to assert that unsafe destinations are rejected with zero HTTP sends; allowed DNS HTTPS and explicitly permitted local development endpoints reach the handler but still do not return a fake qualified receipt. RED [CI 43904739193](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43904739193) proves the missing development flag before implementation. Issue #85 closed after exact final-main [CI 43905297835](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43905297835), SHA `fab01d607fdbe0f6abf298ed1e38be42a1b55b9d`, all four jobs successful.

**Security limit:** No DNS is resolved at URI validation time; DNS rebinding, malicious DNS returning private/link-local IPs, system HTTP proxy and network egress bypasses remain unmitigated by this static check. Operators **must** enforce independently configured connection-time IP/network allowlists and egress policies for each approved TSA in both Azure and on-prem. See [OWASP SSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) and [ADR 0054](../adr/0054-rfc3161-endpoint-uri-development-loopback.md). No external qualified timestamp/Trusted List/certificate revocation/WORM claims are introduced; pilot state remains `Unverified`.

## No implicit forward proxy for TSA HTTP requests (#86; ADR 0055)

The named `external-tsa` `HttpClient` now creates a dedicated `HttpClientHandler` with `UseProxy=false`, **in addition** to `AllowAutoRedirect=false` and `UseCookies=false`. On .NET 10 `UseProxy` otherwise defaults to `true` and could automatically select a proxy from the operating system or `HTTPS_PROXY`/`ALL_PROXY`. With this policy, the RFC 3161 digest-bearing request does not silently go through an inherited **application-level forward proxy**. The provider still validates HTTPS DNS endpoint URI and response status/MIME/DER. No proxy credentials or `Proxy` object are configured. The rest of TemporalMark's HTTP clients (e.g. Keycloak) are unaffected.

**Deployment contract:** Both on-prem and Azure need approved **direct** TCP/443 outbound routing, a verified TSA DNS name and appropriate TLS/CA configuration. Deployments that require a corporate explicit forward proxy for outbound HTTPS will fail to reach the TSA until a separately reviewed proxy feature is implemented and tested; do not bypass the policy by editing the handler at deployment time. This policy does not stop transparent routing proxies, service mesh interception, DNS rebinding, private/link-local DNS answers or malicious local root certificates. Network egress firewall/destination allowlist and connection-time policy are still required.

Run the new TDD regressions:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161NoAmbientProxyTests
```

RED evidence: [CI 43907504241](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43907504241) failed precisely two tests on test-only `main` SHA `47f0d5c`, proving inherited `UseProxy=true` before implementation. Close issue #86 only after a **four-job successful CI run on the exact final main SHA**. See [ADR 0055](../adr/0055-rfc3161-no-ambient-forward-proxy.md), open QTSP parent #15 and evidence/legal release blockers #17/#13.

Official references: [.NET 10 UseProxy default](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.useproxy?view=net-10.0), [.NET DefaultProxy environment behavior](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclient.defaultproxy?view=net-10.0).
