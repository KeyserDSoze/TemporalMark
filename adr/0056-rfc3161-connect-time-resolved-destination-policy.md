# ADR 0056 — Enforce public-IP DNS answers on the socket actually used by the delegated TSA client

Status: Accepted for limited delegated pilot egress hardening (2026-11-16). Child [#87](https://github.com/KeyserDSoze/TemporalMark/issues/87) of open QTSP [#15](https://github.com/KeyserDSoze/TemporalMark/issues/15). **Not qualified; not a complete SSRF, network or service-trust control.**

## Baseline and reviewed decisions

Reviewed ADR [0002](0002-qualified-vs-delegated-timestamping.md), [0052](0052-external-tsa-http-no-redirect-policy.md)–[0055](0055-rfc3161-no-ambient-forward-proxy.md), [threat model](../docs/THREAT_MODEL.md), [TSA runbook](../docs/TSA_HTTP_TRANSPORT.md), `ExternalRfc3161EndpointPolicy`, provider and `ExternalRfc3161TransportPolicy.CreateHandler`, API named client and existing RED/GREEN tests. The deployed TSA URI is server-owned, requires DNS-name HTTPS (except explicitly Development-only loopback), and ambient redirects/cookies/forward proxies are disabled. But `HttpClientHandler` performs DNS lookup on connect with no check on returned IPs; DNS poisoning/rebinding can route HTTPS connections to private/metadata/network destinations despite HTTPS URI syntax. TLS peer identity validation may reject these connections, but does not replace *connect-time* network egress controls and can be affected by local trust configuration.

## Decision

1. Replace the **dedicated named `external-tsa` handler only** with `SocketsHttpHandler` configured `AllowAutoRedirect=false`, `UseCookies=false`, `UseProxy=false`; `Credentials`, `DefaultProxyCredentials` and `Proxy` remain null; no automatic decompression. The handler uses Microsoft .NET 10's `ConnectCallback`, which receives the original `HttpRequestMessage` and DNS endpoint for a *new* connection. API passes `IHostEnvironment.IsDevelopment()` as explicit `allowDevelopmentLoopback`, never tenant-controlled. Provider continues to check URL before sending.
2. For **each new connection**, apply `ExternalRfc3161EndpointPolicy.Validate` to the *actual initial request URI*, verify its authority equals the callback DNS host/port, then resolve with `Dns.GetHostAddressesAsync(host, cancellationToken)`. Inspect every answer **before opening any socket**; refuse empty result, any mixed public+private result, IPv4/IPv6 loopback, RFC1918, 100.64/10 CGN, IPv4 link-local/metadata, IPv4 benchmark/documentation/multicast/reserved, IPv6 link-local/ULA/multicast/documentation/transition/mapped address. This conservative policy denies some special-purpose addresses that might be globally routable, intentionally. Only explicit Development loopback *URI* may resolve to a nonempty list of exclusively loopback IPs. Ordinary HTTPS DNS TSA names require all globally routable IPv4/IPv6 answers.
3. Open the socket **to a selected approved `IPAddress`**, not a hostname, preventing a second DNS resolution between validation and connect. On connect failure, other pre-vetted answers may be tried; no rejected answer may be used. Return `NetworkStream(socket, ownsSocket:true)` to the platform. HTTPS TLS/SNI hostname verification and trust stores remain under the stock `SocketsHttpHandler`; **do not** insert any certificate validation bypass.
4. Preserve 20s client timeout, nonce/imprint CMS and RFC3161 200/MIME/DER checks, <=1 MiB response, and `Unverified` persistence. Update legacy handler tests from `HttpClientHandler`-only property `UseDefaultCredentials` to the `SocketsHttpHandler.Credentials`/proxy property checks. Never modify Keycloak/IdP clients.
5. **TDD:** commit ADR first, then new failing resolver/handler/live-local TCP tests on `main`; observe RED; implement policy, named-handler wiring, update docs. Close #87 only on exact final `main` SHA with all backend/frontend/docker-smoke/terraform green.

## Availability/operational tradeoffs and residual risks

- All DNS answers must pass; split DNS returning even one private/ULA/metadata address **fails connectivity**, not partial bypass. DNS results are checked once per new connection, not per HTTP request on a reused pooled connection. Operators must plan approved DNS, direct egress firewall and TLS CA trust in **on-prem and Azure**. A private-address internal TSA/forward proxy is deliberately unsupported in production without separate audited policy work. Development HTTP(S) localhost still works only in explicit Development.
- The callback blocks *private/nonroutable addresses actually resolved* and prevents post-validation DNS re-resolution during connect. It does **not** prove the DNS answer belongs to the approved QTSP, protect against a publicly routable malicious destination/DNS tampering, transparent proxy/service mesh, local root compromise, custom resolver/route injection, or provide IP/CIDR operator allowlist. Outbound subnet/firewall restrictions remain independently necessary.
- It does not make a time stamp qualified: TSA signer EKU/path/revocation, historical EU Trusted Lists, time service/UTC, WORM and CAB release checks remain open #15/#17/#13. Data remain `Unverified`.

## Authoritative references

- [Microsoft .NET 10 SocketsHttpHandler.ConnectCallback](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.socketshttphandler.connectcallback?view=net-10.0)
- [Microsoft .NET 10 SocketsHttpConnectionContext](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.socketshttpconnectioncontext?view=net-10.0)
- [Microsoft Dns.GetHostAddressesAsync](https://learn.microsoft.com/en-us/dotnet/api/system.net.dns.gethostaddressesasync?view=net-10.0)
- [Microsoft Socket.ConnectAsync(IPAddress,port)](https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.socket.connectasync?view=net-10.0)
- [IANA IPv4 special-use registry](https://www.iana.org/assignments/iana-ipv4-special-registry)
- [IANA IPv6 special-use registry](https://www.iana.org/assignments/iana-ipv6-special-registry)
