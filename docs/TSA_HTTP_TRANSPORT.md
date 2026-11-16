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

RED proof: [CI 43902202323](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43902202323) failed 10 targeted cases on the test-first commit. #84 closes only after four-job GREEN on final exact `main` SHA. The response Content-Type is **untrusted metadata**; it cannot establish signature trust, revocation status, historical EU Trusted List qualification, UTC traceability or WORM integrity. The record continues to be `Unverified`. See [ADR 0053](../adr/0053-rfc3161-strict-http-response-envelope.md). Parent #15, preservation #17 and compliance #13 remain OPEN.
