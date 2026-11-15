# FIDO MDS signed-JWS cryptographic preflight — **NOT TRUSTED** (#58)

**Status: ISOLATED CANDIDATE ONLY.** This component is **not** a production FIDO Metadata Service validator, credential enrollment workflow, manufacturer attestation trust evaluation, or certificate-revocation validator. Do not connect it to registration, API/PWA, CLI, SQL or tenant decisions. The V015/V016 SQL registrar interlock and suspended registrar CLI remain unchanged. See [ADR 0029](../adr/0029-isolated-mds-jws-chain-candidate-without-revocation-trust.md) and parent [#57](https://github.com/KeyserDSoze/TemporalMark/issues/57).

## What code tests actually prove

`src/backend/infrastructures/TemporalMark.Infrastructure/WebAuthn/ReviewerMdsJwsSignatureCandidateVerifier.cs` accepts a **caller-selected TEST X.509 root**, a FIDO-like compact signed JWT, and a test clock. It has **no network access** and uses `Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler` for JWS cryptographic validation. It permits only a conservative RS256 test subset, rejects untrusted `x5u`, `jku`, `jwk`, `crit`, unsupported/disguised JWS algorithms, duplicate header names, malformed/noncanonical base64url and oversized inputs. A strictly bounded `x5c` array supplies the **leaf signing key**; only a test-supplied root may terminate the path, via `X509ChainTrustMode.CustomRootTrust`, no certificate auto-downloads, exact path-byte equality and UTC certificate validity. The signed `iat` header must be recent and a signed positive `no` serial is required. Only a **SHA-256 digest and serial** escape.

The tests create ephemeral **separate RSA keys** for a v3 X.509 test CA and JWS signer at runtime. They sign real RS256 compact JWS test tokens and exercise actual maintained Microsoft.IdentityModel signature verification, untrusted alternate roots, changed payload/signature, wrong signing key, injected chain, missing/duplicate/malicious JWT headers, unsupported algorithms, expired/not-yet-valid certificates, stale/future `iat`, missing/invalid serial, and overlong input. **No test private key or certificate is committed.** Tests are not proof of real FIDO hardware or trustworthiness of a manufacturer signer.

### Why even the positive is UNAPPROVED

The function intentionally sets **`X509RevocationMode.NoCheck`** for the **test-only** chain construction. This establishes signature and chain *structure*, **not** that any signing certificate was not revoked. There is no signed proof of CRL/OCSP, independently approved FIDO root, monotonic serial checkpoint, attestation AAGUID mapping, latest model status or real on-prem/Azure trust flow. The caller-supplied test root might be attacker-controlled. It returns **only** `ReviewStatus=UNAPPROVED` and `PolicyStage=JWS_CHAIN_ONLY_REVOCATION_UNVERIFIED`, not an accepted signer, verified FIDO metadata, credential, grant, attestation certificate or authorization. Never interpret a positive result as "safe metadata".

## Production release blockers: #57/#55

The [FIDO MDS changelog](https://fidoalliance.org/mds-changelog/) documents August 2026 transition from GlobalSign R3 to **R46** and an August 31 R3→R46 cross-certificate in `JWT x5c[2]`. R3/cross-cert expires **2029-03-18**. Current pinned Fido2 **4.3.3** still hardcodes R3 in its metadata repository and has separate revocation branches, including `X509RevocationMode.NoCheck` under system-trusted paths. The **test-only** RS256/x5c exact-path policy in this slice is **not claimed fully compatible** with the 2026 transitional x5c or multiple official algorithms. Before real use, an independent security/CAB review must implement and verify:

1. Independently sourced/approved R46 root rotation (with documented retirement of R3), official signed BLOB JWS/x5c, issuer and chain semantics, **revocation of every relevant signer-chain certificate on all OS paths**; CRLs/OCSP must be current, authentic, signed, bounded and fail closed on network/verification outage. No permissive "host trusted" or self-asserted root fallback.
2. Secure on-prem offline/air-gap signing-root and CRL transfer; Azure constrained/private egress and SSRF defenses; resilient but fail-closed refresh, audit, retention, and immutable monotonic signed `no`/digest checkpoint surviving host restarts and rollbacks. FIDO 3.1.1 cautions against relying on `nextUpdate` alone.
3. Independent AAGUID/certification/status policy, attestation model-specific certificate path validation (distinct from the **MDS BLOB signing chain**), signer custody and role authority with reviewer-held registered key, registrar's independently witnessed consent and atomic SQL one-time decision. DPIA, incident/recovery procedures and CAB review before deployment.

**On-prem and Azure are equally blocked**, with no mandatory Azure dependency introduced. #57/#55/#53/#44/#50/#46/#38 stay OPEN. No WORM/QTSP/eIDAS qualification is claimed by this cryptographic test.

## References

- [ADR 0029](../adr/0029-isolated-mds-jws-chain-candidate-without-revocation-trust.md)
- [MDS metadata preflight runbook](WEBAUTHN_MDS_POLICY.md)
- [FIDO MDS changelog](https://fidoalliance.org/mds-changelog/)
- [FIDO MDS 3.1](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html)
- [Fido2 4.3.3 tagged metadata repository](https://github.com/passwordless-lib/fido2-net-lib/blob/4.3.3/Src/Fido2/Metadata/Fido2MetadataServiceRepository.cs)
