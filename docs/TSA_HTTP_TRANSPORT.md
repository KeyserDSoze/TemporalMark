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

The default four-job GitHub CI must pass on the **exact final main commit** before closing #83. No real upstream TSA request is made by these unit tests.

## Not covered

This transport setting is not a comprehensive SSRF defense: network policy must separately restrict outbound destinations, DNS, proxies, private addresses and metadata services. A compromised configured TSA or egress proxy remains a threat. Do not infer trust or qualified legal status from a cryptographically signed token alone: signer revocation/history, certificate chain, qualified status at issuance time, policy, key and algorithm conformance, timestamp accuracy and WORM evidence are tracked in #15/#17/#13. Persisted pilot records remain `Unverified`.

## Normative and runtime references

- [Microsoft .NET 10 HttpClientHandler.AllowAutoRedirect](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.allowautoredirect?view=net-10.0)
- [RFC 9110 §15.4.8/15.4.9 HTTP redirect semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.8)
- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161)
