# ADR 0071 — Runtime-current disposable MDS JWS signer fixture for isolated non-authorizing tests

Status: Accepted for **test-only regression repair**, 2026-11-18. [#102](https://github.com/KeyserDSoze/TemporalMark/issues/102), child of OPEN MDS trust #57 and CI #20. No WebAuthn registrar or production trust changes.

## Baseline and **observed RED**

Reviewed ADR 0029 (detached unapproved RS256/X.509 MDS JWS candidate), `docs/WEBAUTHN_MDS_JWS_PRECHECK.md`, `src/backend/infrastructures/TemporalMark.Infrastructure/WebAuthn/ReviewerMdsJwsSignatureCandidateVerifier.cs` and `tests/backend/TemporalMark.Provisioner.Tests/ReviewerMdsJwsSignatureCandidateVerifierTests.cs`. Existing fixture declares a static test clock `Now = 2026-11-16T00:00:00Z`. Its ephemeral X.509 JWS signer leaf is valid from that time minus 1 hour until that time plus 2 days: `2026-11-18T00:00:00Z`. At runner time `2026-11-18T09:07Z` this disposable certificate is **actually expired**.

**Observed RED**: [GitHub Actions CI 44272815080](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44272815080/attempts/1), exact main SHA `109f07ff162f8f27f14c9a8c5b54b3e204a6f3c8`: backend 9/9 Domain + 219/219 Business; Provisioner **488 passed, 1 failed of 489**, named `RealRsaSignedPinnedRootChainReturnsOnlyUnapprovedDigestAndSerial`. Stack trace shows denial at `ReviewerMdsJwsSignatureCandidateVerifier.cs:134`, following the maintained `JsonWebTokenHandler.ValidateTokenAsync` returning invalid. Frontend/Terraform success, Docker skipped. The isolated verifier's custom `X509Chain` uses an explicit synthetic `VerificationTime=nowUtc` and may accept the expired-in-real-time signer at Nov 16; the maintained IdentityModel signing-key verifier also applies actual clock semantics. It is **unsafe to relax certificate validation** just to make a frozen positive fixture pass forever.

## Decision

1. Add a **RED-first xUnit fixture certificate validity invariant**: the freshly constructed, disposable positive JWS leaf in protected `x5c[0]` must be valid **at the actual UTC runtime instant** (and still valid for an additional hour) to exercise maintained cryptographic signature verification. The historical static test clock fails this new invariant on Nov 18, matching the already observed positive-test RED.
2. Minimal **GREEN test-only** change: initialize the shared test-case clock once with `DateTimeOffset.UtcNow`, not a hard-coded 2026 date. Keep all existing fixture-relative windows, `iat` freshness, expired and not-yet-valid leaves, wrong signer, wrong root, unsupported algorithms and parser checks. The synthetic signed `nextUpdate` text is a fixture placeholder **not validated as real FIDO metadata**. No production verifier/configuration, API, SQL, WebAuthn enrollment, storage or FIDO root change.
3. Prove the full existing xUnit suite on the exact final documentation-inclusive main SHA, including four original CI jobs via [#101](https://github.com/KeyserDSoze/TemporalMark/issues/101) status context `temporalmark/ci-4-core-jobs`. Do not assert GREEN from merely applying a code edit. Parent #57/#55/#53 and CI #20 remain open.

## Why this does not weaken security

The production-side **isolated candidate** still has explicit custom-root chain validation, maintained `JsonWebTokenHandler` signature and signing-key checks, bounded `iat`, strict header parser and **no CRL/OCSP trust proof**. Every positive candidate remains `UNAPPROVED / JWS_CHAIN_ONLY_REVOCATION_UNVERIFIED`. The V015/V016 registrar SQL interlock and disconnected reviewer credential enrollment are frozen. An independently authenticated FIDO R46 root, full signer-chain revocation, monotonic signed metadata custody, and actual historical qualified TSA status remain unimplemented under #57/#55/#53 and #15/#13.

## References

- [ADR 0029](0029-isolated-mds-jws-chain-candidate-without-revocation-trust.md)
- [Microsoft X509ChainPolicy.VerificationTime](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chainpolicy.verificationtime?view=net-10.0)
- [GitHub observed failing run](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44272815080/attempts/1)
