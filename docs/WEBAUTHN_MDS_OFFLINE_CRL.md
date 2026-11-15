# Offline FIDO MDS CRL signature preflight (#59)

**Status: UNAPPROVED / NON-AUTHORIZING.** This is an isolated test-driven crypto component, **not** a production trusted FIDO metadata repository, approved certificate issuer, or operational revocation service. See [ADR 0030](../adr/0030-offline-direct-issuer-crl-cryptographic-preflight.md), security parent [#57](https://github.com/KeyserDSoze/TemporalMark/issues/57) and [#55](https://github.com/KeyserDSoze/TemporalMark/issues/55). The V015/V016 SQL registrar freeze, suspended CLI and old approval SQL decision blocker remain unchanged.

## Tested behavior

`src/backend/infrastructures/TemporalMark.Infrastructure/WebAuthn/ReviewerMdsOfflineCrlCandidateVerifier.cs` uses maintained **BouncyCastle.Cryptography 2.7.0** to parse DER-encoded **X.509 v2 CRLs**, verify the CRL signature using the *direct issuer certificate public key*, reject revoked leaf serials, ensure issuer CA key permissions (`keyCertSign` and `cRLSign`), and reject invalid CRL `thisUpdate`/`nextUpdate` and certificate validity. It checks one directly issued X509 v3 leaf against one explicit issuer: a .NET `CustomRootTrust` path establishes the direct certificate signature with no host CA fallback. **This issuer is selected by the caller and is therefore untrusted**. It does not download CRLs or obtain issuer certificates from URLs.

It rejects malformed, missing, oversized and noncanonical DER; unrelated CA keys and CRL issuers; changed CRL signatures; missing, stale, future or excessively long validity; unsupported critical CRL/entry extensions, delta/indirect CRLs, revoked serials and missing `cRLSign` authority. No alternate CRL, missing-CRL fallback, unchecked-root promotion or recovery override exists.

The xUnit fixtures create temporary .NET RSA CA/leaf keys and test certificates at runtime, then use **real BouncyCastle** X.509 v2 CRL generation and signing. No private or public test trust anchor is seeded into configuration or committed to the repository. This is a **real cryptographic CRL-signature and serial-regression fixture**, not a successful production device or vendor-attestation trust test.

The only possible successful result is `ReviewStatus=UNAPPROVED`, `PolicyStage=CRL_SIGNATURE_CHECK_ONLY_ROOT_UNTRUSTED`, and an SHA-256 digest of the CRL. No raw CRL, certificate, signer public key or trusted/ACTIVE credential escapes. A caller-supplied issuer may be malicious, so **even a correctly signed non-revocation result is not an authoritative FIDO revocation assertion**.

## What remains OPEN in #57/#55

1. Independently approve and pin the real FIDO MDS GlobalSign **R46** root, respecting August 2026 R3→R46 `x5c[2]` cross-certificate transition and R3 expiry **2029-03-18**. Verify a real FIDO MDS signed JWT chain, all intermediate CA and signer certificate CRLs/OCSP **at every hop**, not only this test-only direct leaf. Audit all Fido2 4.3.3 revocation branches, including its `NoCheck` system-trusted path.
2. Support only explicitly reviewed CRL distributions, signed/authenticated CRL refresh, CRL number/issuer AKI and CDP scope, delta and delegated issuers if required, and persistent monotonic replay/rollback checkpoints. On-prem offline/air-gap and Azure constrained egress must fail closed when a required CRL is missing, revoked, unavailable or stale; SSRF protections and signed offline transfers are mandatory. No local mutable timestamp/CRL is independent evidence of freshness.
3. Bind **CRL** to the actual verified MDS JWS signing chain from ADR 0029 and only then to status policy and an independently verified authenticator AAGUID/attestation chain. No code in this increment wires the isolated components together. Any production trust, reviewer signer-key registration, explicit two-person registrar consent, one-time atomic SQL decision and key revocation remain separate projects. Privacy/DPIA, CAB/AgID review and evidence retention must be addressed before qualification.

Both Azure and on-prem run the same application code; neither gains a root or trust from this change. Do not describe cryptographic CRL tests as eIDAS qualified, WORM preserved or manufacturer-certified hardware provenance.

## Sources

- [RFC 5280 CRL processing](https://www.rfc-editor.org/rfc/rfc5280)
- [BouncyCastle.Cryptography 2.7.0 on NuGet](https://www.nuget.org/packages/BouncyCastle.Cryptography/2.7.0)
- [BouncyCastle 2.7.0 X509Crl](https://github.com/bcgit/bc-csharp/blob/release-2.7.0/crypto/src/x509/X509Crl.cs)
- [FIDO MDS root rollover](https://fidoalliance.org/mds-changelog/)
- [ADR 0030](../adr/0030-offline-direct-issuer-crl-cryptographic-preflight.md)
