# External RFC 3161 TSA — fail-closed outbound HTTP transport (#83)

**Pilot only. NOT QUALIFIED.** ADR [0052](../adr/0052-external-tsa-http-no-redirect-policy.md) documents the security decision. Parent [#15](https://github.com/KeyserDSoze/TemporalMark/issues/15) stays open for RFC 3161/PKI and EU Trusted List verification.

## Deployment configuration

`TimestampProvider:Url` and `TimestampProvider:Id` are owned by the operator, not the tenant. The API requires an absolute HTTPS URL outside the explicit **development-only** localhost HTTP exception. The named `external-tsa` HttpClient retains a 20-second request timeout but installs `ExternalRfc3161TransportPolicy.CreateHandler(builder.Environment.IsDevelopment())` as its primary handler.

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

The named `external-tsa` `HttpClient` now creates a dedicated `SocketsHttpHandler` with `UseProxy=false`, **in addition** to `AllowAutoRedirect=false` and `UseCookies=false`. On .NET 10 `UseProxy` otherwise defaults to `true` and could automatically select a proxy from the operating system or `HTTPS_PROXY`/`ALL_PROXY`. With this policy, the RFC 3161 digest-bearing request does not silently go through an inherited **application-level forward proxy**. The provider still validates HTTPS DNS endpoint URI and response status/MIME/DER. No proxy credentials or `Proxy` object are configured. The rest of TemporalMark's HTTP clients (e.g. Keycloak) are unaffected.

**Deployment contract:** Both on-prem and Azure need approved **direct** TCP/443 outbound routing, a verified TSA DNS name and appropriate TLS/CA configuration. Deployments that require a corporate explicit forward proxy for outbound HTTPS will fail to reach the TSA until a separately reviewed proxy feature is implemented and tested; do not bypass the policy by editing the handler at deployment time. This policy does not stop transparent routing proxies, service mesh interception, DNS rebinding, private/link-local DNS answers or malicious local root certificates. Network egress firewall/destination allowlist and connection-time policy are still required.

Run the new TDD regressions:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161NoAmbientProxyTests
```

RED evidence: [CI 43907504241](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43907504241) failed precisely two tests on test-only `main` SHA `47f0d5c`, proving inherited `UseProxy=true` before implementation. Close issue #86 only after a **four-job successful CI run on the exact final main SHA**. See [ADR 0055](../adr/0055-rfc3161-no-ambient-forward-proxy.md), open QTSP parent #15 and evidence/legal release blockers #17/#13.

Official references: [.NET 10 UseProxy default](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.useproxy?view=net-10.0), [.NET DefaultProxy environment behavior](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclient.defaultproxy?view=net-10.0).

## DNS answer verification at the actual TCP connection (#87, ADR 0056)

**New trust boundary:** URI syntax alone cannot prevent a DNS hostname from resolving to an internal or metadata-service IP. The named outbound TSA `HttpClient` therefore uses the .NET 10 `SocketsHttpHandler.ConnectCallback`. Before each **new** direct connection, the callback checks the actual initial request URI, its DNS hostname/port, and the entire resolved address set from `Dns.GetHostAddressesAsync`. An empty response or **any** nonpublic/forbidden answer fails the connection: the client does not silently discard the bad address and try the good one. It then connects a `Socket` using an **approved IPAddress** from that exact validated answer, without making a second hostname resolution. The normal .NET HTTPS/TLS certificate and SNI handling remains active; no insecure certificate callback or custom trust-bypass is installed.

The conservative denied ranges include IPv4 loopback, RFC 1918, 100.64/10 carrier NAT, 169.254/16 cloud metadata/link-local, documentation/benchmark/protocol-assignment and multicast/reserved, along with IPv6 ULA/link-local/multicast, mapped IPv4, documentation and transition networks. Both eligible public IPv4 and IPv6 addresses are supported. Some special-use IPs that may have limited public routability are deliberately denied. A DNS reply containing *both* 8.8.8.8 and 10.0.0.1 is **denied completely**. This is a protective category check, **not an approved QTSP IP allowlist or independently verified DNS answer**.

In **Development** only, when the request URI is itself localhost/127.0.0.1/::1, the same callback allows nonempty DNS results consisting **entirely of loopback addresses**. The API supplies this flag exclusively from `builder.Environment.IsDevelopment()`; the default for any other caller is false. This supports the local HTTP TSA integration smoke without enabling private or metadata IP destinations for ordinary TSA DNS hosts.

`ExternalRfc3161ResolvedDestinationTests` cover blocked/allowed IPv4 and IPv6, empty and mixed DNS records, explicit Development-only loopback, handler callback configuration, a default-handler TCP loopback denial and a **real loopback TCP** integration under the development flag:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161ResolvedDestinationTests
```

TDD RED: [GitHub Actions 43911461382](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43911461382), test-only commit `e1e4182b`, failed due to missing address policy and connection callback. #87 **closed** after exact final `main` SHA `9ac9fc61cf7d3e1ab35cfd3836557152c7ba0ed7` passed all four jobs in [CI 43912615969](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43912615969).

### Deployment limits and requirements

Both Azure and open-source on-prem deployments must permit **direct** outbound connectivity from the API to the operator-reviewed public DNS TSA on approved TLS ports, set network-level deny rules for metadata/internal addresses, and review its certificates and DNS provenance. A private-only TSA endpoint, internal HTTP proxy or split DNS mixing private IPs is deliberately incompatible with this pilot policy; a future such deployment requires separately approved security architecture. Normal HTTPS CA validation is preserved. Connection reuse means validation occurs for each new socket, not again for each request on an existing pooled socket. Public malicious IPs returned by compromised DNS, transparent interception, malicious trusted CAs, routes and network overlay changes are **not** solved; firewall/effective egress identity policy must be independently enforced. These network checks do not establish QTSP legal qualification, historical EU Trusted List status, revocation history or WORM custody. All receipts still have `Unverified` status. See [ADR 0056](../adr/0056-rfc3161-connect-time-resolved-destination-policy.md), [Microsoft SocketsHttpHandler.ConnectCallback](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.socketshttphandler.connectcallback?view=net-10.0), #15/#17/#13.

## TSA socket lease and explicit TLS 1.2/1.3 transport profile (#88, ADR 0057)

After the #87 `ConnectCallback` was introduced, every **new** TCP connection validates the complete DNS answer list and dials an approved IP. But pooled connections are reused without rerunning that callback. The dedicated `external-tsa` handler now sets `PooledConnectionLifetime = TimeSpan.FromSeconds(60)`: an expired idle connection is replaced, and the next new socket re-evaluates DNS. **Active requests are not interrupted**, and a 60-second pool lifetime is **not a hard DNS freshness deadline**. The existing 20-second `HttpClient.Timeout`, no-proxy/no-redirect/no-cookie, IP classification and <=1 MiB response protections are preserved.

The handler also explicitly sets `SslOptions.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13`, allowing **only TLS 1.2 or TLS 1.3 negotiation** for HTTPS TSA calls. Servers supporting only TLS 1.0/1.1 will not work. This is a deliberate TemporalMark pilot policy (not an eIDAS qualification statement); it restricts the normally OS-selected protocol choices and will require review if future secure versions become available. The transport does **not** set any custom certificate-validation callback, permissive trust callback or signer certificate exception: TLS hostname, SNI, chain checks and trusted roots remain platform-managed. A valid HTTPS peer alone does not prove that a signed RFC 3161 token is legally qualified or that its CMS signer is trusted.

Tests in `tests/backend/TemporalMark.Provisioner.Tests/ExternalRfc3161TlsAndConnectionLifetimeTests.cs` inspect the **actual named transport factory**, both normal and explicit Development loopback modes, fresh handler independence and stock certificate-validation settings:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161TlsAndConnectionLifetimeTests
```

TDD RED: [GitHub Actions 43915676967](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43915676967) on test-only SHA `763f124e` failed four targeted cases, with the other 231 provisioning tests and all Domain/Business tests passing. #88 **closed** after all four jobs passed on exact final `main` SHA `6b25d7bd3d021707ad44f5ad5263d5088f6a73de` in [CI 43916214609](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43916214609). See [ADR 0057](../adr/0057-rfc3161-bounded-connection-lifetime-and-tls-floor.md), [Microsoft pool lifetime](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.socketshttphandler.pooledconnectionlifetime?view=net-10.0), and [Microsoft SslProtocols](https://learn.microsoft.com/en-us/dotnet/api/system.security.authentication.sslprotocols?view=net-10.0).

**Operator work remains:** Test actual QTSP HTTPS interoperability and trusted system CA stores across both Azure and on-prem, independently enforce egress/TSA identity, monitor connection failures/clock drift and document certificate chain/revocation and historical EU Trusted List service status. Neither TLS 1.2/1.3 nor re-resolving DNS qualifies the provider, closes #15, ensures WORM (#17) or completes Italian/eIDAS legal launch controls (#13). Persisted stamps remain `Unverified`.

## Exclusive critical timestamp signing EKU of the verified CMS signer (#89; ADR 0058)

[RFC 3161 §2.3](https://www.rfc-editor.org/rfc/rfc3161#section-2.3) requires the timestamp authority's signing certificate to contain **exactly one critical Extended Key Usage (EKU) extension** and **only** the key-purpose OID `id-kp-timeStamping` (`1.3.6.1.5.5.7.3.8`). A certificate for HTTPS `serverAuth`, code signing or `anyExtendedKeyUsage` is not interchangeable with a dedicated TSA signer, even if it also includes timestamping EKU. A noncritical or duplicate EKU is likewise rejected in the pilot.

After the existing RFC 3161 request/response DER, signature, ESSCertID/ESSCertID2 and nonce/SHA-256 imprint checks, the provider now captures `token.VerifySignatureForHash(..., out signerCertificate)` and invokes `ExternalRfc3161SignerCertificatePolicy.Validate` on **that actual verified signer**, before constructing any provider result. The guard rejects a null signer, missing/noncritical/duplicate extension, wrong or multiple key-purposes, and malformed ASN.1. Failures return only a generic provider response error; untrusted raw certificate contents are not logged. The operator and tenant cannot bypass this guard. This is not a network call or a new trust-store override.

Regression tests generate disposable short-lived **self-signed X.509 fixtures** solely to test EKU decoding, including one good EKU and multiple fail-closed cases:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161SignerCertificatePolicyTests
```

The tests do **not** make self-signed certificates trusted, do not generate legally valid qualified timestamps and do not prove end-to-end interoperability with a genuine QTSP. **TDD RED**: [CI 43919547198](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43919547198) on test-first SHA `778bf077` failed compilation only because the policy was not yet present; domain and business tests remained green. #89 **closed** after four-job GREEN on exact final `main` SHA `1906437f615cf0f03797890ab54cc08fe6747edd`, [CI 43920557678](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43920557678).

**Unresolved #15/#17/#13:** RFC3161 EKU exclusivity by itself says nothing about who issued the TSA certificate, independent certification path/trust anchors, certificate/key revocation at signing time, qualified service status in **historical EU Trusted Lists**, cryptographic algorithm validity, independently verified UTC, retained validation material, WORM custody or AgID/CAB qualification. Signed pilot records still persist as `Unverified` and may never be described as qualified based only on these checks. See [ADR 0058](../adr/0058-rfc3161-critical-exclusive-timestamp-signer-eku.md) and [Microsoft Rfc3161TimestampToken.VerifySignatureForHash](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamptoken.verifysignatureforhash?view=net-10.0).

## Required, operator-reviewed RFC 3161 signing certificate SHA-256 pin (#90; ADR 0059)

An RFC 3161 reply with a valid self-consistent CMS signature, nonce, imprint and sole critical EKU is **not necessarily from the operator-approved TSA**. Before this change, a signer could generate its own untrusted certificate and response satisfying those cryptographic checks; TemporalMark did not bind the verified CMS signer to an independently approved signing certificate. The provider now requires a server-owned `TimestampProvider:SignerCertificateSha256` **whenever an external TSA URL is configured**. A missing, blank or malformed pin fails closed with a generic configuration error **before an outbound HTTP POST**. The default disabled `TimestampProvider:Url=""` needs no pin.

### Operator configuration (both Azure and on-prem)

1. Obtain the **actual RFC3161 CMS token signer X.509 certificate** from a trusted, independently verified QTSP/operator channel; it is **not** the HTTPS transport/TLS server certificate. Independently review its source, validity, purpose and change approval. The certificate hash is **SHA-256 over the entire DER-encoded leaf certificate**, not the SHA-1 value in .NET's default `Thumbprint`, not a subject name, public key/SPKI hash, issuer or certificate serial number.
2. For a verified **PEM** signer certificate, compute its fingerprint offline:

   ```sh
   openssl x509 -in reviewed-rfc3161-tsa-signer.pem -outform DER | openssl dgst -sha256
   ```

   Copy **only the 64 hexadecimal characters** output after `=`. Configure the server-controlled environment variable `TimestampProvider__SignerCertificateSha256` (or `TimestampProvider:SignerCertificateSha256` in secured application configuration). Both uppercase and lowercase ASCII hexadecimal are supported. **Do not include** `SHA256`, colons, `0x`, whitespace, line breaks or multiple comma-separated values. `TimestampProvider:Url` and `TimestampProvider:Id` remain operator controlled.
3. Reissuing or rotating that **leaf certificate** changes its DER SHA-256 fingerprint even if it retains the same private key. Review and deploy the new fingerprint through your ordinary change-control process **before** the provider switches. This pilot deliberately supports **one approved leaf at a time**; it has no trust-on-first-use, remote auto-discovery, permissive bypass or multi-pin rollover. A non-matching signer causes issuance to fail, not an automatic fallback. Operations requiring overlapping CA/signer rollover need a separately reviewed implementation.
4. Do **not** log or submit raw stamp imprints, certificate private keys or token contents to a generic diagnostic pipeline. An approved fingerprint is public metadata but is still security-critical configuration subject to change auditing. The signer identity is checked **after** the existing RFC3161 CMS signature/imprint/nonce and strict critical-only EKU checks against the **same cryptographically verified signer**, using .NET 10 `X509Certificate2.GetCertHash(HashAlgorithmName.SHA256)` and `CryptographicOperations.FixedTimeEquals`. Any nonmatching or absent signer fails with a generic `TimestampProviderResponseException`; no record is returned.

Test the policy and network preflight with synthetic certificates and a counting HTTP handler:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161SignerPinPolicyTests
```

TDD RED evidence: [CI 43927346733](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43927346733) on tests-only `main` SHA `a3e06c8615e7d9d51ec5081b1ec762a3b547c93b` failed precisely on missing signer-pin policy/constructor parameter; old business/domain tests passed. The strict pin protects against *unapproved new signer leaf identity*, not a compromised approved signer key, compromised operator configuration, forged public DNS routing, PKIX chain/path failure, revocation at signing instant, service qualified-status history, WORM or independent UTC. Actual QTSP service qualification must be established separately under open #15, #17 and #13. All pilot timestamps remain `Unverified`. See [ADR 0059](../adr/0059-rfc3161-operator-approved-signer-certificate-sha256.md).

Authoritative .NET references: [GetCertHash(HashAlgorithmName)](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate.getcerthash?view=net-10.0), [FixedTimeEquals](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptographicoperations.fixedtimeequals?view=net-10.0).

## Mandatory operator-approved RFC 3161 service policy OID (#91, ADR 0060)

A TSA leaf signing certificate can issue timestamp tokens under more than one **TSA policy**, including non-qualified/test service types. Having a valid signed CMS message, nonce/imprint, sole critical timeStamping EKU and approved SHA-256 signing-leaf fingerprint **does not bind the response to the intended service policy**. In [RFC 3161 §2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2), the optional `TimeStampReq.reqPolicy` selects the requested service policy, and `TSTInfo.policy` **MUST** be the same OID when requested.

`TimestampProvider:PolicyOid` is now required **whenever `TimestampProvider:Url` is configured**. The API reads it from trusted server configuration and passes it to the provider; no tenant/request/headers or TSA auto-discovery controls it. `ExternalRfc3161ApprovedPolicy.ParseRequiredPolicyOid` rejects missing, blank, ambiguous, noncanonical or oversized OIDs **before constructing/sending an outbound request**. The request's DER now includes `reqPolicy` via `.NET 10 Rfc3161TimestampRequest.CreateFromHash(..., requestedPolicyId: reviewedPolicy, nonce: ..., requestSignerCertificates: true)`. After processing the response and validating the signed CMS/imprint/nonce, signer critical-only EKU and operator-approved leaf fingerprint, the provider explicitly requires `token.TokenInfo.PolicyId` to **equal** that reviewed value before returning `ProviderTimestamp`. The .NET timestamp response parser may also enforce `reqPolicy` matching, but the application-level check is retained as a security invariant. An unsupported or different provider policy fails issuance; there is no silent fallback.

### Deployment and operations

1. Independently obtain the **genuine TSA service policy document and OID** for the operator-approved service from authenticated QTSP materials. Verify the policy describes the intended service type, certificate/signature requirements and any qualified-service historical constraints. An OID value alone is **not proof** of eIDAS-qualified status.
2. Configure the **same operator-approved OID** on Azure and on-prem with `TimestampProvider__PolicyOid` (or `TimestampProvider:PolicyOid` in secured server config), alongside `TimestampProvider__Url`, `TimestampProvider__Id` and `TimestampProvider__SignerCertificateSha256`. The value must be canonical ASCII dotted-decimal, at least two arcs and within parser bounds (e.g., **`1.2.3.4.5` is syntax only, not an approved or qualified policy**). No whitespace, Unicode digits, textual friendly names, prefixes, leading zero arcs or comma-delimited policy lists.
3. If a QTSP changes or retires its policy OID, **stop issuance** until the new service policy, signer identity and historical qualified-service status have been independently reviewed, approved and redeployed. A single mandatory OID per deployment is intentionally restrictive; overlapping multi-policy transitions require a separate audited change. Disabled TSA (empty URL) still needs neither signer pin nor policy.
4. No qualified status is inferred: validated receipt evidence continues as `Unverified`. Real signer's X.509 path/revocation, historical EU Trusted List service status, approved cryptographic algorithms, WORM custody and CAB/AgID qualification remain separate unresolved controls in open #15/#17/#13.

Tests include deterministic ASCII OID grammar, matching/mismatched signed policy, pre-send failure on missing policy, and **captured/decoded actual RFC3161 request** verifying `RequestedPolicyId`, SHA-256 imprint, nonce and `certReq`:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161ApprovedTsaPolicyTests
```

Test-first RED: [CI 43931749155](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43931749155), SHA `6391bb4e8dc6eb996169a9ef85c9d77b3cd908d7`, failed on the intended missing policy and provider constructor symbols while domain/business/frontend/Terraform stayed green. See [ADR 0060](../adr/0060-rfc3161-operator-approved-request-and-signed-token-policy.md), [Microsoft CreateFromHash](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamprequest.createfromhash?view=net-10.0), [RFC3161](https://www.rfc-editor.org/rfc/rfc3161).

## Offline X.509 signer path to an operator-approved CA root (#92, ADR 0061)

Even a signature-valid RFC 3161 token with a sole critical timeStamping EKU (#89), an operator-approved **leaf** SHA-256 fingerprint (#90), and an exact service policy OID (#91) **does not by itself demonstrate that the signer chains to an independently reviewed CA**. TemporalMark's delegated pilot now also requires a server-controlled `TimestampProvider:TrustAnchorCertificateBase64Der` when an external TSA URL is configured. The provider validates this setting **before HTTP transmission** and, after all existing CMS/nonce/imprint, signer EKU/pin and policy checks, builds an X.509 chain for **that same cryptographically verified CMS signer** to the approved root. An absent/malformed root or an untrusted/expired/incomplete chain causes the request to fail; no token is returned or recorded. Disabled TSA (empty URL) needs no anchor.

### Operator preparation — Azure and on-prem

1. Independently review which **X.509 root CA certificate** is authorized for the *RFC 3161 CMS signing certificate* by the actual QTSP. Do **not** use the HTTPS/TLS server's certificate, the TSA leaf, a randomly selected intermediate or a CA simply because it is trusted by the host OS. Confirm root owner/subject, DER SHA-256 fingerprint, policy, source authenticity and deployment approval **out of band**; an operator-provided anchor is a *trust decision*, not an automatic QTSP verification.
2. Export exactly one reviewed root **certificate** (no private key) as DER and encode it as standard canonical **single-line Base64**:

   ```sh
   openssl x509 -in reviewed-tsa-root.pem -outform DER | openssl base64 -A
   ```

   Set `TimestampProvider__TrustAnchorCertificateBase64Der` (or secured `TimestampProvider:TrustAnchorCertificateBase64Der`) to **just the Base64 characters**. The parser rejects PEM markers, whitespace/newlines, noncanonical/multiple/trailing DER, oversized input (>64 KiB), a non-self-issued certificate, missing critical CA basic constraints or missing critical `KeyCertSign` key usage. `appsettings.json` leaves this blank intentionally. The companion required settings remain `TimestampProvider__Url`, `TimestampProvider__Id`, `TimestampProvider__SignerCertificateSha256` and `TimestampProvider__PolicyOid`.
3. Review the TSA's returned **intermediate CA certificates**: the validator uses `token.AsSignedCms().Certificates` for intermediates and requires the resulting path to end at the **exact approved DER root**. A missing intermediate must be fixed at the provider/approved integration, not silently fetched from the internet or a local certificate store. Root changes require explicit operator review, configuration rollout and signed audit trail. Both Azure and on-prem use the same behavior; there is no Azure-only trust service or system-root fallback.
4. This first offline step explicitly uses `.NET 10 X509ChainPolicy.TrustMode=CustomRootTrust`, `CustomTrustStore` containing **only** the operator-approved root, `ExtraStore` with the CMS bundle, `DisableCertificateDownloads=true`, `VerificationFlags=NoFlag`, and **`RevocationMode=NoCheck`**. It evaluates the path using **current UTC time** (`VerificationTime=DateTime.UtcNow`); it does **not** establish historical certificate validity or revocation at the claimed RFC3161 token issuance instant, and does not automatically check CRLs, OCSP or historical EU Trusted Lists. Even if a chain passes, the receipt remains `Unverified`. Build a separate, independently witnessed **signing-time revocation and historical qualified service-status** proof before considering production/legal launch under #15/#13; WORM/long-term custody remains #17.

The regression suite generates disposable untrusted RSA **root→TSA leaf** and **root→intermediate→TSA leaf** certificates and checks authorized/offline path building, wrong roots, missing intermediates, expired leaf, non-CA/invalid anchor and pre-send failures; no real QTSP trust is claimed:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161CertificateChainPolicyTests
```

TDD RED evidence: [CI 43942439055](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43942439055) on tests-only `745a5853adaa49a12061dfcb1cb39b1516747bc3` failed on expected missing offline chain policy/constructor symbols, with Domain/Business/frontend/Terraform green; [ADR 0061](../adr/0061-rfc3161-operator-approved-offline-signer-x509-chain.md) was committed first. See [Microsoft X509ChainPolicy](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chainpolicy?view=net-10.0) and [Rfc3161TimestampToken.AsSignedCms](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamptoken.assignedcms?view=net-10.0).

## Live signed `genTime` consistency and issuance-time X.509 path (#93; ADR 0062)

RFC 3161's `TSTInfo.genTime` is a UTC timestamp **asserted by the TSA and covered by its CMS signature**. The previous #92 offline signer path checked X.509 certificate validity at the API host's **current** time, not the signed timestamp issuance time, and did not reject otherwise CMS-valid replies that claimed an absurdly old or far-future `genTime`. The live delegated provider now combines two independent checks:

1. Immediately **before** sending the actual RFC 3161 request, capture the API host's UTC `requestStartedAt`. Capture `responseReceivedAt` **after the entire bounded HTTP response body** has been received. After verifying RFC3161 DER, nonce/SHA-256 imprint, CMS signature, the **actual verified signer's** critical sole timeStamping EKU, reviewed leaf SHA-256 pin and signed TSA policy OID, call `ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime` using the **CMS-signed** `token.TokenInfo.Timestamp`. Require an inclusive window from **requestStartedAt minus 120 seconds** to **responseReceivedAt plus 120 seconds**. A reversed local clock (response before request), extreme timestamp, stale/backdated or future-dated signed token fails with a generic response error and produces no receipt. The clock tolerance is a fixed pilot operational restriction; it is **not** the token's asserted `accuracy` field, a qualified UTC traceability claim or a tenant-configurable override. Exact-window and time-zone offset boundary regressions cover the behavior.
2. **Only after** the signed time passes that live consistency window, build the same operator-custom-root `X509Chain` for the same verified CMS signer **at the signed issuance instant**, setting `X509ChainPolicy.VerificationTime = token.TokenInfo.Timestamp.UtcDateTime` explicitly (disabling `VerificationTimeIgnored`). Preserve `CustomRootTrust` with one approved DER CA root, intermediates limited to the received CMS bundle, `DisableCertificateDownloads=true`, `VerificationFlags=NoFlag` and **`RevocationMode=NoCheck`**. This avoids substituting today's leaf validity for certificate validity when the TSA claims it signed. Tests with disposable CA-signed leaves valid only in a selected historical window verify the explicit X.509 time selection; the live HTTP freshness gate separately prevents replay of those historic tokens as new issues.

**Operator prerequisites and limits:** Both on-prem and Azure hosts must maintain reliable **NTP/chrony/system UTC time synchronization**, monitor drift and log incidents independently. Misconfigured/skewed host clocks can reject legitimate QTSP replies or allow misleading claims within the 120s window; this is a **bounded plausibility test, not independently witnessed clock evidence**, precision certification, or legally qualified time. The response timeout remains 20 seconds, and the RFC 3161 `accuracy` and `ordering` fields need separate policy/assurance evaluation. Nothing here verifies historic CRLs/OCSP, revocation at `genTime`, historical EU Trusted List **service-type/qualification status**, the TSU UTC(k) time source, real provider interoperability, WORM custody (#17) or CAB/AgID obligations (#13). **#15 remains open** and all pilot records remain `Unverified`.

TDD RED: [CI 43956887816](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43956887816) on tests-first SHA `e8154d3b7915349b54e91ce2f563b93017bb2158` failed on missing time policy / explicit X.509 time overloads while Domain/Business remained green. See [ADR 0062](../adr/0062-rfc3161-live-gen-time-and-issuance-time-x509-path.md), [RFC 3161 §2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2) and [Microsoft .NET X509ChainPolicy verification time semantics](https://learn.microsoft.com/en-us/dotnet/core/compatibility/cryptography/7.0/x509chainpolicy-verification-time).

Local focused regression command:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter 'FullyQualifiedName~ExternalRfc3161IssuanceTimePolicyTests|FullyQualifiedName~ExternalRfc3161CertificateChainPolicyTests'
```

## Offline, operator-reviewed full CRL for directly root-issued TSA signer (#94; ADR 0063)

*Historical scope of #94: since #95/ADR 0064, live issuance also supports **exactly one CA intermediate** when both the root's and intermediate's signed CRLs are explicitly reviewed and supplied; see the next section. The original direct-root profile remains available.*

The earlier offline custom-root X.509 path (#92) deliberately used `RevocationMode=NoCheck`. A chain with a valid CA signature and certificate validity at bounded signed `genTime` (#93) cannot by itself establish that its TSA signing certificate has not been revoked. **This new conservative pilot control** requires one independently obtained, fully signed issuer **certificate revocation list (CRL)** covering the *same signed issuance instant* and **only** supports a **direct approved root CA → TSA signing leaf**. A root→intermediate→leaf chain is now **rejected by live delegated issuance** until independently verified per-issuer CRLs/OCSP can cover every non-root certificate. The separate X509 path unit tests still cover multi-hop chain construction; they do not establish multi-hop revocation.

### Operator configuration and offline evidence handling

1. Independently identify the **CRL issuer for the actual RFC3161 CMS signing certificate**, its distribution point/scope, CA identity and published full CRL. Verify origin and approve the CRL through an authenticated CA/QTSP channel, not an unauthenticated link. The issuer must be the **same reviewed CA root** as `TimestampProvider:TrustAnchorCertificateBase64Der`. The root must authorize `CrlSign`; its certificate and `SubjectKeyIdentifier` are used to bind the CRL's issuer and authority key identifier. A CRL signed by a different CA with an identical issuer name fails signature verification.
2. Convert exactly one authenticated **complete DER CRL** to canonical single-line Base64 (no PEM markers or whitespace). For example, if your approved source distributes a DER `issuer.crl`:

   ```sh
   openssl crl -inform DER -in issuer.crl -noout -issuer -lastupdate -nextupdate
   openssl base64 -A -in issuer.crl
   ```

   Configure `TimestampProvider__IssuerCrlBase64Der` (or secured `TimestampProvider:IssuerCrlBase64Der`) via the **server deployment**, alongside the already mandatory TSA URL/id, approved signer DER SHA-256, service policy OID and root DER certificate. Azure and on-prem use the same option. No user/tenant request may supply a CRL. Missing, malformed, oversized (>1 MiB), noncanonical, unsupported/delta/indirect CRL input **fails before any HTTP POST**.
3. The validator enforces **RFC 5280 v2 complete CRL** structure, inner/outer `sha256WithRSAEncryption` algorithm equality, CRL issuer DER X.500 DN matching reviewed root and signer issuer, authenticated RSA SHA-256/PKCS#1 v1.5 signature over the original `TBSCertList`, approved-root CA `CrlSign`, root SKI matching CRL AKI, mandatory `CRLNumber`, and signed `thisUpdate <= token.genTime < nextUpdate`. A signer serial **appearing anywhere in the authenticated CRL is rejected**, even if its listed revocation date is after `genTime`: this first slice intentionally favors conservative refusal over retrospective claims about revocation reason/invalidity date. Unsupported entry extensions, unknown critical CRL semantics, indirect/delta lists, signature tampering, wrong root and chain intermediates fail closed rather than silently passing. Neither DNS nor the host's system CRL cache is used.
4. Operationally **rotate and re-approve the complete CRL before `nextUpdate`**. An expired/not-yet-effective CRL blocks issuance, not merely raises a warning; do not disable the guard to recover. Preserve the exact externally received CRL and evidence of independent authentication/approval in an auditable archive **outside** the normal application configuration as a separate operational obligation; TemporalMark does **not yet** persist independent CRL/OCSP proof, long-term trusted-list snapshots, witnesses, or qualification. Plan an incident procedure if a signer is revoked, distribution changes, or any intermediate CA becomes necessary. No automatic fetch or trust-on-first-use is implemented.
5. **Security/legal boundary:** `X509Chain.RevocationMode=NoCheck` stays explicit because path building remains offline. The dedicated **separate CRL verifier** now covers only the direct root→leaf case. It does **not** provide complete historical all-hop PKIX revocation (including OCSP), CA-qualified service identity at issuance, EU Trusted List service status, eIDAS qualification, QTSP HSM/UTC(k), proof preservation, replay/rollback-safe CRL history or WORM (#17); #15 and #13 remain OPEN. The exact CRL freshness window is a **pilot operational constraint**, not an EU legal validation result. Even passing this check, the receipt remains `Unverified`.

Tests use disposable .NET `CertificateRevocationListBuilder.Build` **genuinely signed** CA CRLs (clean, revoked, wrong root with same DN, tampered, stale/future, corrupt, multi-hop denied) and do not use real QTSP credentials:

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161IssuerCrlPolicyTests
```

TDD RED evidence: [CI 43961838074](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43961838074) on test-first SHA `7ba52b4bec7d9fdd7c78cb4b88cf56189546816a` failed on missing CRL verifier and provider named arguments, with existing Domain/Business/frontend/Terraform green; [ADR 0063](../adr/0063-rfc3161-offline-direct-issuer-signed-full-crl.md) committed first. References: [RFC5280 §5.1](https://www.rfc-editor.org/rfc/rfc5280#section-5.1), [CertificateRevocationListBuilder.Build](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.certificaterevocationlistbuilder.build?view=net-10.0).

## Two complete per-issuer CRLs for one X.509 intermediate (#95; ADR 0064)

The delegated RFC3161 pilot now validates the **actual CustomRootTrust certificate path** selected from the CMS response with **complete signed revocation coverage at each non-root certificate**, for exactly two supported path shapes:

- **Direct:** reviewed root CA → verified TSA signing leaf. `TimestampProvider:IssuerCrlBase64Der` is mandatory and must be a genuine **root-signed full CRL**; **leave `TimestampProvider:IntermediateIssuerCrlBase64Der` empty**. If a second CRL is configured unnecessarily, issuance fails rather than silently ignoring it.
- **One intermediate:** reviewed root CA → intermediate CA → verified TSA signing leaf. **Both** root-signed `TimestampProvider:IssuerCrlBase64Der` **and** intermediate-signed `TimestampProvider:IntermediateIssuerCrlBase64Der` are required. First verify that the **intermediate CA certificate serial is not revoked** on the authenticated root CRL; then verify that the **exact cryptographically verified RFC3161 signer leaf serial is not revoked** on the authenticated intermediate CA CRL. Each check uses the *immediate issuer selected by the previously validated X.509 path*, not a matching-subject certificate included arbitrarily in the CMS response. Both CRLs must be valid at the **same bounded CMS-signed** `TSTInfo.genTime`. A missing or invalid CRL at either level rejects issuance.

### Operator rollout, Azure and on-prem

1. Independently review the TSA signer path and each CA's authenticated **full CRL** from that CA's legitimate CRL distribution source and relevant service policy. For one intermediate, retain the existing reviewed **root-signed** full DER CRL configuration, and independently obtain the **intermediate CA-signed** full DER CRL for the TSA leaf. Convert its exact DER bytes to canonical single-line standard Base64, for example `openssl base64 -A -in reviewed-intermediate-issuer.crl`. The root and intermediate CRLs cannot be substituted for one another.
2. Configure the **server only**, identically on both Azure and on-prem, with `TimestampProvider__IntermediateIssuerCrlBase64Der` (or secured `TimestampProvider:IntermediateIssuerCrlBase64Der`). Leave it blank if the actual pinned signer is issued directly by the reviewed root. When non-empty, the value must pass the same strict complete-v2-CRL DER and Base64 parser **before any HTTP request**. For an intermediate signer chain, a blank value fails **after token verification** because chain length and actual selected intermediate are only known then. Never accept a CRL URL, an ambient OS cache, tenant input or a guessed issuer certificate.
3. Rotate **both** full signed CRLs with documented independent approval **before their respective `nextUpdate`**, monitoring root and intermediate changes. Each issuer's `CrlSign`, issuer DER name, RSA SHA-256 issuer signature, root/intermediate SKI–CRL AKI, CRLNumber and `thisUpdate <= signed genTime < nextUpdate` are checked separately. A listed certificate is conservatively rejected **regardless of its reported revocation date**. A wrong-key CA with the same subject DN cannot authorize the TSA signing leaf's CRL, nor can an unverified CMS-bundled cert override the path selected by custom root X.509 validation.
4. A longer chain with **two or more intermediate CAs** remains **unsupported and fails closed**, even if a plausible CRL is supplied. Delta, indirect, partially reason-partitioned and unsupported signature formats, CRL/OCSP network retrieval, historic issuer status, rollback-resistant CRL history and immutable proof custody are also **not implemented**. This is not a complete generic RFC5280 §6.3 validator, nor proof of eIDAS-qualified QTSP status, preserved CRL review, UTC(k), historical EU Trusted List service qualification, WORM (#17) or CAB/AgID conformity (#13). Open #15 remains the parent; all pilot marks remain `Unverified`.

Focused tests generate disposable RSA root, intermediate and signer certificates and **two genuinely issuer-signed CRLs**. Revoking either intermediate or leaf, wrong signer keys with identical DN, missing CMS intermediate, swapped/malformed/stale CRLs and superfluous CRL in the direct path fail closed.

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161TwoHopIssuerCrlTests
```

[ADR 0064](../adr/0064-rfc3161-intermediate-issuer-complete-crl-coverage.md) · [RFC5280 §6.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.3) · [RFC10007 cRLSign clarification](https://www.rfc-editor.org/rfc/rfc10007.html).

## Operator-reviewed signed CRLNumber minimums (#96; ADR 0065)

RFC 5280 §5.2.3 defines `CRLNumber` as a **monotonically increasing signed sequence for a given CRL issuer and scope** (the extension must be noncritical). The earlier #94/#95 checks authenticated each full CRL's issuer RSA signature, scope-restricted extension profile, AKI/SKI, revoked-serial list and `thisUpdate <= bounded CMS-signed genTime < nextUpdate`, but did not use the **signed** `CRLNumber`. A *still-current*, correctly signed **older CRL** could therefore replace the independently reviewed newer CRL in operator configuration.

The delegated TSA provider now requires separately **operator-approved per-issuer lower bounds** on that signed CRL number. This is a **static deployment-owned anti-rollback threshold**, not a monotonically witnessed or cryptographically preserved CRL history.

- For **every configured external TSA**, provide `TimestampProvider__IssuerCrlNumberFloor` (or `TimestampProvider:IssuerCrlNumberFloor`) as the **minimum accepted signed root-issued CRLNumber**. It applies to root→TSA direct and root→intermediate CA→TSA paths.
- Only if `TimestampProvider__IntermediateIssuerCrlBase64Der` is configured, also provide `TimestampProvider__IntermediateIssuerCrlNumberFloor`. This is the **minimum signed intermediate-CA-issued CRLNumber** and is checked separately against its CRL, not against the root's numbering sequence. With no intermediate CRL, leave the intermediate floor blank; a nonempty floor without that CRL fails pre-send.
- Each floor must be **canonical positive ASCII decimal** (e.g. `1`, `42`, `1208925819614629174706176`), with no leading zeroes, `+`/`-`, whitespace, exponent, locale digits or values requiring over 20 unsigned octets. Missing/invalid floors or inconsistent presence of the second CRL/floor **reject before any imprint is transmitted**. `appsettings.json` leaves both blank so the delegated pilot cannot be activated by accident. Disabled/no external TSA URL still needs no floor.
- For each CA, the application reads the CRLNumber from the **DER-encoded signed TBSCertList**, validates RFC5280's mandatory noncritical CRLNumber and up-to-20-octet range, and after verifying that **same CRL's issuer identity and RSA SHA256 signature**, requires `signedCRLNumber >= approvedOperatorFloor`. The direct path applies one comparison; the intermediate path applies **both independent comparisons**. A correctly signed lower-numbered CRL, even if still within its `nextUpdate` interval and clean of the signer serial, is rejected. Equal-number repeat validation is allowed; a higher authenticated number passes the configured lower bound.
- **Operator rotation process:** independently authenticate the CRL provenance and the CA/scope, compare its signed CRLNumber with the **last approved** number held in independently controlled records, and approve a new floor that does **not decrease** before/alongside the replacement CRL. Use change control, audit and rollback prevention in **both** Azure and on-prem deployments. A server administrator who can roll back **both** CRL bytes and the floor defeats this guard. Same-number CRL equivocation, delayed CRL distribution, independent last-seen monotonic witness custody, archived revocation evidence, historical EU Trusted List qualified service status and OCSP/reason-partitioned validation are still **OPEN requirements**. The software does not update or preserve this floor independently.
- Existing SHA-256 leaf pinning, signed policy OID, live signed genTime consistency, CustomRootTrust PKIX chain and complete full issuer CRL signature/freshness/revocation checks are unchanged. No tenant-input/ambient-OS trust, automatic CRL fetch, Azure-only dependency or qualified assertion is introduced. **Records remain `Unverified`.**

Focused regression tests use disposable RSA root→TSA and root→intermediate→TSA chains with **genuinely signed CRLs numbered 1, 2 and 4**, checking equal/higher floors, signed lower-number rejection, independent root/intermediate checks, >32-bit numbers and strict missing/malformed preflight. Tests do not supply production QTSP credentials.

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161CrlNumberFloorTests
```

TDD RED: [Actions CI 44009723455](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44009723455) tests-only SHA `c11665a654a7eaeb1ffa13c60f353080680108f9` failed on missing floor parser/issuer validation/provider named args after [ADR 0065](../adr/0065-rfc3161-operator-crl-number-minimum-floors.md) was committed first.

See [RFC5280 §5.2.3](https://www.rfc-editor.org/rfc/rfc5280#section-5.2.3), [ADR 0065](../adr/0065-rfc3161-operator-crl-number-minimum-floors.md), [threat model](THREAT_MODEL.md).

## Strict TSA signer end-entity and signing-only Key Usage (#97; ADR 0066)

The delegated pilot verifies the cryptographic RFC 3161 CMS signer, enforces the *sole critical* timeStamping EKU, the deployment-approved signer SHA-256 fingerprint, signed policy, pinned-root issuance-time PKIX chain and issuer-signed full CRLs. **Separately**, it now rejects a CMS signer certificate unless it has **exactly one valid non-CA Basic Constraints extension** (no path length) and exactly one parseable Key Usage containing **only** digitalSignature and/or nonRepudiation (contentCommitment), with at least one of those signing flags present. CA=true, missing/duplicated/malformed extensions, signing as a CA or CRL issuer, encipherment and key agreement are denied. Critical and noncritical end-entity Basic Constraints/Key Usage are accepted; the existing RFC3161 **EKU must still be critical**.

Requiring Basic Constraints even on an end entity, and requiring a restricted signing-only Key Usage, is an intentionally **strict TemporalMark pilot interoperability policy**. Do **not** claim RFC3161 unconditionally mandates every part of this local profile. Operators evaluating an authentic QTSP should compare its published certificate profile before enabling the connector; incompatible certificates fail closed and require independently reviewed ADR/code/tests, not a bypass or disabled verifier. This checks certificate metadata, **not real private-key exclusivity**, historic Trusted List qualified service status, authenticated CRL source or independently witnessed CRL rollback protection. All records remain **Unverified**, #15/#17/#13 are open. The same provider code is used for Azure and on-prem, with no new settings or tenant overrides.

TDD regression: `tests/backend/TemporalMark.Provisioner.Tests/ExternalRfc3161TsaLeafProfilePolicyTests.cs` uses ephemeral X.509 keys for positive signing-only and negative CA/missing/malformed/duplicate KU+BC scenarios. ADR first on main, then test-first RED commit `9a51ccbd8e2bc57c230084e15f4703a6fb56bdae`, policy implementation `8670fd39c6f473d158ca154ad60b0adfe5b55a28` and actual provider call `ec3b4e773799e27ad3c85663b7d664f2d4acf660`. Full green CI on the final documentation-inclusive SHA **remains to be verified** before #97 can close.

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161TsaLeafProfilePolicyTests
```

Sources: [RFC 3161 §2.3](https://www.rfc-editor.org/rfc/rfc3161#section-2.3), [RFC 5280 §4.2.1.3](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3) and [§4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9), [ADR 0066](../adr/0066-rfc3161-tsa-signer-end-entity-key-usage.md).

## Strict bounded CMS-signed TSTInfo accuracy (#98; ADR 0067)

**Deliberately restrictive delegated pilot; NOT a UTC(k) or qualification proof.** [RFC 3161 §2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2) makes `TSTInfo.accuracy` **optional**: when it is absent, the stated accuracy may instead be obtained from other means such as the authenticated `TSAPolicyId`. TemporalMark does **not** implement that policy-to-accuracy interpretation. For now the delegated TSA path requires the **otherwise signature-, nonce-, imprint-, signer-, path- and issuer-CRL-verified** token to explicitly include `TSTInfo.accuracy` and declare **0 through 1,000,000 microseconds** (one second maximum, inclusive). A missing value, negative/oversized value, overflow or claim above one second causes a generic TSA response error; the application stores no receipt from it.

The .NET 10 `Rfc3161TimestampTokenInfo.AccuracyInMicroseconds` nullable property reads the actual TSTInfo field from the signed token; TemporalMark does not read a TSA HTTP header or tenant-provided number. This local one-second **claim filter is not a legal qualified-accuracy threshold** and is not an authenticated measurement of the issuer's UTC clock, HSM, UTC(k) topology, network timing, audit, or incident response. A compromised TSA can sign a false accuracy statement, and a properly qualified provider may legitimately leave this optional field out under an approved policy. Incompatible QTSP receipts **fail closed** pending operator-reviewed interoperability tests, documentation and a new ADR — do not remove the guard ad hoc.

The same code applies to on-prem/Azure; no new deployment setting, database migration, external dependency or tenant override is introduced. Parent #15, preservation #17, legal/CAB/AgID #13 and full historical service qualification remain OPEN, all stored pilot records stay `Unverified`. See [ADR 0067](../adr/0067-rfc3161-strict-signed-tstinfo-accuracy.md).

New focused regression: `tests/backend/TemporalMark.Provisioner.Tests/ExternalRfc3161SignedAccuracyPolicyTests.cs` includes direct boundary tests and genuine .NET DER-encoded/decoded `TSTInfo` fixtures; **these are not CMS-signed or real QTSP test tokens**. RED-first main commit `e5c4fda`, wrapper RED `5bc88a4`, implementation `615a121`, actual provider hook `dfdeea9`. **No GitHub CI RED/GREEN outcome has yet been independently verified**: #98 must not close until all four workflow jobs pass on the exact final docs-inclusive main HEAD.

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161SignedAccuracyPolicyTests
```

Sources: [RFC 3161 §2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2) and [.NET Rfc3161TimestampTokenInfo](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamptokeninfo?view=net-10.0).

## Fail-closed response-stream I/O outages (#99; ADR 0068)

The configured TSA client uses `HttpCompletionOption.ResponseHeadersRead`, so the response may advertise **200 OK** and `application/timestamp-reply` while the actual socket stream fails to open, or may return a partial DER prefix before a read fails. A raw `System.IO.IOException` from those reads previously bypassed the provider's HttpRequestException/timeout normalization and could reach an unhandled API error. The delegated pilot now converts transport `IOException` into a generic `TimestampProviderUnavailableException` (API 503), **without retaining/returning any partially read bytes** or leaking the raw I/O exception message. This also catches I/O errors from the send path. The existing status/MIME guard, 1 MiB cap, full DER/CMS verification, 120-second signed genTime window, signer KU/EKU, operator root/CRL floors and signed claimed accuracy rules remain unchanged. A complete but invalid DER response still maps to a TSA response error (502). Explicit caller cancellation must remain a cancellation rather than a fabricated successful response.

**Operational caveat:** an unavailable response may still correspond to a request *received* or even processed by the upstream TSA. This change is not external issuance idempotency, an exactly-once billing guarantee, a safe automatic retry mechanism, or a record of legal delivery. Do not retry blindly without an independently reviewed nonce/transaction correlation and quota policy. Temporary transport interruptions must never generate `Unverified` evidence or masquerade as qualified timestamp proof.

Focused RED-first test `tests/backend/TemporalMark.Provisioner.Tests/ExternalRfc3161StreamingIoFailureTests.cs` injects `IOException` during send, stream acquisition and **after a delivered DER prefix**, asserts sanitized unavailability and unchanged invalid-DER behavior, and preserves caller cancellation. Uses only disposable root/CRL test fixtures; no live QTSP. ADR first `dc135237`, test-first `ca5f382c`, implementation `4d877568`. **Actual exact-final-main 4/4 Actions result must still be verified** before closing #99; previous #97/#98 are separately pending CI. Parent #15, WORM #17 and CAB/AgID #13 remain open.

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161StreamingIoFailureTests
```

Reference: [ADR 0068](../adr/0068-rfc3161-response-stream-io-fail-closed.md), [Microsoft NetworkStream.ReadAsync](https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.networkstream.readasync?view=net-10.0).

## Signed TSTInfo extension profile: reject all unreviewed semantics (#100; ADR 0069)

**Conservative unqualified pilot interoperability restriction, not a universal RFC3161/eIDAS rule.** RFC3161 §2.4.2 defines an **optional** `TSTInfo.extensions [1] IMPLICIT Extensions` set in the cryptographically signed token. The .NET 10 `Rfc3161TimestampTokenInfo.HasExtensions` and `GetExtensions()` APIs expose these fields, but their mere presence and a valid CMS signature do not mean TemporalMark understands what each OID requires. The pilot now **rejects any nonempty signed TSTInfo extension set**, even if every extension is marked noncritical. A token with no TSTInfo extension is accepted by this particular gate only after signature, nonce, imprint, signer KU/EKU/pin, approved policy, signed live `genTime`, custom-root PKIX, signed full issuer CRLs and the fixed claimed-accuracy bound pass. A rejected token is not stored.

**Do not confuse** these *TSTInfo* extensions with required *X.509 certificate* extensions, such as EKU, Key Usage and Basic Constraints, which remain independently validated. RFC3161 §2.4.1's rule requiring a TSA to reject unknown **request** extensions is not a blanket requirement that an RFC3161 client always reject any unrecognized **response TSTInfo** extension. This is an explicit **TemporalMark restriction**; a real compliant QTSP with useful critical or noncritical token extensions will be rejected until the exact OID/DER and semantic trust implications are approved by operators, tested and recorded in a new ADR. Never add a catch-all allowlist without interpretation.

TDD: ADR 0069 before code [`f00a77e`](https://github.com/KeyserDSoze/TemporalMark/commit/f00a77e80aafbce960e3da0807d7aa72f1b06e57), RED-first genuine .NET DER TSTInfo fixture [`75cc860`](https://github.com/KeyserDSoze/TemporalMark/commit/75cc860123e59800d14b313dcca7fb3a412cf2b7), standalone policy [`249e4e1`](https://github.com/KeyserDSoze/TemporalMark/commit/249e4e1ff5e3c46f200633cd4df93647a5326f75), provider invocation [`240c47e`](https://github.com/KeyserDSoze/TemporalMark/commit/240c47edceae6ae657ee5fd65e417e59c3f35463). These fixtures are unsigned DER TSTInfo and **not** cryptographically validated QTSP tokens; they exercise decoded semantics only. Actual RED/GREEN GitHub Actions outcome has **not been independently retrieved**; keep #100 OPEN pending exact final docs-inclusive 4/4 CI. Parent #15, WORM #17, legal #13, and other CI-pending #97–#99 remain OPEN; records `Unverified`. Identical on-prem/Azure runtime; no tenant-configurable bypass.

```sh
dotnet test tests/backend/TemporalMark.Provisioner.Tests/TemporalMark.Provisioner.Tests.csproj --configuration Release --filter FullyQualifiedName~ExternalRfc3161TstInfoExtensionPolicyTests
```

References: [ADR 0069](../adr/0069-rfc3161-signed-tstinfo-extension-interoperability.md), [RFC3161 §2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2), [.NET 10 `Rfc3161TimestampTokenInfo`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamptokeninfo?view=net-10.0).
