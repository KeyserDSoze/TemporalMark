# ADR 0058 — Validate RFC 3161 critical exclusive time-stamping EKU of actual CMS signer

Status: Accepted for delegated pilot defense-in-depth (2026-11-16). Child [#89](https://github.com/KeyserDSoze/TemporalMark/issues/89) of open [#15](https://github.com/KeyserDSoze/TemporalMark/issues/15). **EKU conformance is not legal or qualified TSA status.**

## Baseline and authoritative rule

Reviewed [ADR 0002](0002-qualified-vs-delegated-timestamping.md), [ADR 0052](0052-external-tsa-http-no-redirect-policy.md) through [ADR 0057](0057-rfc3161-bounded-connection-lifetime-and-tls-floor.md), [operator guide](../docs/TSA_HTTP_TRANSPORT.md), [threat model](../docs/THREAT_MODEL.md), and `ExternalRfc3161TimestampProvider` and its existing real HTTP/DER tests. It already requires a nonce, SHA-256 imprint, signed CMS token, exact 200 OK and RFC3161 MIME and bounded DER, but calls `token.VerifySignatureForHash(..., out _)` and discards the validated signer certificate. .NET documents that verifier checking the required EKU OID, ESSCertID(2), certificate validity interval covering token time and cryptographic signature/imprint, **not** a separate guarantee that the EKU extension is critical and the *only* permitted key purpose.

[IETF RFC 3161 §2.3](https://www.rfc-editor.org/rfc/rfc3161#section-2.3) requires the TSA signer certificate to have **only one instance** of the EKU extension (OID `2.5.29.37`), **critical**, and with KeyPurposeID `id-kp-timeStamping` (OID `1.3.6.1.5.5.7.3.8`). TemporalMark interprets this strictly: exactly one critical EKU extension and exactly one key-purpose OID in it, equal to the time-stamping value. A certificate combining timestamping with TLS serverAuth, code signing or anyExtendedKeyUsage is not dedicated to time-stamping and fails this pilot profile.

## Decision

1. A dedicated `ExternalRfc3161SignerCertificatePolicy.Validate(X509Certificate2? signerCertificate)` checks **the actual signer returned from cryptographic verification**. Refuse null signer, missing EKU, duplicate EKU extensions, noncritical EKU, wrong purpose OID, multiple purposes, malformed/unknown extension bytes. No platform certificate store search or new network lookup is done here.
2. In `ExternalRfc3161TimestampProvider.RequestAsync`, retain existing signed RFC3161 `timeRequest.ProcessResponse`, exact DER length, nonce, SHA-256 imprint and `VerifySignatureForHash`. Change the `out _` to `out var signerCertificate` and call the policy **only after VerifySignatureForHash returned true**, before generating `ProviderTimestamp`; preserve generic `TimestampProviderResponseException` error with no certificate/ASN.1 data in logs. A cryptographic parser failure remains rejected. Do not introduce any positive bypass or change evidence status.
3. TDD order: commit ADR first on `main`, then tests that generate **disposable self-signed X.509 fixtures** with normal .NET `CertificateRequest` and cover valid critical-only timestamp EKU, missing/wrong/noncritical/multi-purpose/any purpose and null, observe GitHub RED; then policy and provider call, docs and final exact-head 4/4 GREEN CI.
4. The tests' self-signed certificates are **not** valid QTSP certificates and cannot yield qualified timestamps; use them only to test EKU profile parsing. This local EKU check is deliberately independent from chain, revocation, historical EU Trusted List and legal qualification.

## Important residual gaps

The library verifier reports that a signature and token imprint match; **it does not establish trust in the signing key** merely because EKU is correct. Actual issuance requires independent approved QTSP service identity, X.509 chain and certificate path/revocation at signing instant, historical EU Trusted List service type/status, cryptographic algorithm and TSU key/time controls, and long-term preserved validation data. No release gate moves to qualified without #15/#17/#13. The pilot persists all receipts as `Unverified`. Both Azure and on-prem use the same parser and trust-status semantics.

## References

- [RFC 3161 §2.3 TSA identification and EKU exclusivity](https://www.rfc-editor.org/rfc/rfc3161#section-2.3)
- [Microsoft .NET Rfc3161TimestampToken.VerifySignatureForHash](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamptoken.verifysignatureforhash?view=net-10.0)
- [Microsoft .NET X509EnhancedKeyUsageExtension](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509enhancedkeyusageextension?view=net-10.0)
