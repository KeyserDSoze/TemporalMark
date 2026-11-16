# ADR 0057 — Bound delegated TSA pooled connection lifetime and negotiate TLS 1.2/1.3 only

Status: Accepted for the limited delegated pilot transport-hardening scope (2026-11-16), child [#88](https://github.com/KeyserDSoze/TemporalMark/issues/88) of open [#15](https://github.com/KeyserDSoze/TemporalMark/issues/15). **No claim of QTSP qualification or complete SSRF/network trust.**

## Reviewed baseline

Reviewed [ADR 0002](0002-qualified-vs-delegated-timestamping.md), [ADR 0052](0052-external-tsa-http-no-redirect-policy.md) through [ADR 0056](0056-rfc3161-connect-time-resolved-destination-policy.md), [TSA operator runbook](../docs/TSA_HTTP_TRANSPORT.md), [threat model](../docs/THREAT_MODEL.md), the actual `ExternalRfc3161TransportPolicy.CreateHandler` and .NET 10 provisioning handler tests, as well as the API-only named `external-tsa` HTTP configuration and real provider. Previous #87 added `SocketsHttpHandler.ConnectCallback` to resolve, validate **every** DNS answer, reject private/loopback/metadata replies and dial a validated IP without a second hostname lookup. This callback applies to newly established connections, while HTTP/1.1 and HTTP/2 may reuse pooled connections; no explicit maximum pool connection age was set.

Microsoft [.NET 10 SocketsHttpHandler.PooledConnectionLifetime](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.socketshttphandler.pooledconnectionlifetime?view=net-10.0) documents that its default is `InfiniteTimeSpan`, that expiration does **not** terminate in-flight requests, and that finite lifetime is used to reflect DNS/network changes. [.NET 10 SslProtocols](https://learn.microsoft.com/en-us/dotnet/api/system.security.authentication.sslprotocols?view=net-10.0) describes `None` as OS-managed default. That OS-managed default is normally recommended for general .NET clients, but this pilot's specific restricted TSA policy deliberately makes its minimum negotiated TLS version explicit and repeatably testable.

## Decision and TDD sequence

1. Only the **named external TSA SocketsHttpHandler** sets `PooledConnectionLifetime = TimeSpan.FromSeconds(60)`. Every newly established socket must run the existing DNS answer / direct-IP callback. Expired *pooled* connections are replaced rather than indefinitely reused. Do not treat 60 s as a guaranteed hard DNS revalidation SLA: an active request can outlive the threshold, and 20 s HTTP timeout is separately retained.
2. Explicitly configure `SslOptions.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13` on that handler. This **deliberately restricts** TLS negotiation to TLS 1.2 and TLS 1.3; servers requiring obsolete SSL/TLS1.0/TLS1.1 or unsupported future versions will fail. Neither `RemoteCertificateValidationCallback` nor any permissive `CertificateRevocationCheckMode` nor `ClientCertificates` is set. The platform continues to validate the TSA peer's TLS certificate chain/hostname/SNI using its trust store. TLS transport validation alone is **not** validation of the RFC3161 token signing certificate or qualification.
3. Preserve `UseProxy=false`, `AllowAutoRedirect=false`, `UseCookies=false`, `AutomaticDecompression=None`, and the #87 connection-time public-IP policy. Only the `external-tsa` named handler changes, not IdP, operator or other HTTP clients. Production/Development endpoint policy stays identical.
4. Commit this ADR first on `main`; add RED tests against the *actual handler* and observe failed assertions in GitHub Actions; then implement green transport properties and update `docs/`. Close child #88 only after **all four** CI jobs pass on the **exact final SHA** of main.

## Residual risks / operator constraints

Finite lifetime is a **bounded re-connect schedule**, not DNS SEC, a trusted IP ownership allowlist or anti-interception proof. DNS returning an attacker-controlled **public** IP, transparent network proxies, public-CA misissuance, malicious local root trust, routing changes and compromised QTSP remain outside this change. Some QTSPs may not support the restricted TLS versions; operators must validate interoperability before production and cannot silently weaken the profile. On-prem and Azure require direct allowed egress, firewall/connection-time destination identity and reliable DNS, with parity of functionality. Record state remains `Unverified`; signer certificate EKU/path/revocation, historical EU Trusted Lists, UTC(k), evidence WORM and CAB/AgID qualification remain open (#15/#17/#13).

## Sources

- [Microsoft .NET 10 SocketsHttpHandler.PooledConnectionLifetime](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.socketshttphandler.pooledconnectionlifetime?view=net-10.0)
- [Microsoft .NET 10 SocketsHttpHandler.SslOptions](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.socketshttphandler.ssloptions?view=net-10.0)
- [Microsoft .NET 10 SslProtocols enum](https://learn.microsoft.com/en-us/dotnet/api/system.security.authentication.sslprotocols?view=net-10.0)
