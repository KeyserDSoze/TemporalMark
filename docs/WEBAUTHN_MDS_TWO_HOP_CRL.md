# FIDO MDS — two-hop offline signed CRLs for signer + intermediate (#60)

**Status: CRYPTOGRAPHIC TEST ONLY / UNAPPROVED.** This runbook documents a pure offline regression for one X.509 certificate chain of exactly **three** elements. It does not implement production FIDO Metadata Service root trust, signed BLOB retrieval, metadata authorization, reviewer credential enrollment, CRL/OCSP distribution or any SQL/CLI/API operation. The V015/V016 SQL freeze remains in force. See [ADR 0031](../adr/0031-two-hop-offline-mds-crl-with-untrusted-root.md), parent [#57](https://github.com/KeyserDSoze/TemporalMark/issues/57) and [#55](https://github.com/KeyserDSoze/TemporalMark/issues/55).

## What the tests actually check

`ReviewerMdsOfflineTwoHopCrlCandidateVerifier` requires:

- An original signer X.509 v3 **leaf** bearing DigitalSignature.
- A distinct issuing X.509 v3 **intermediate CA** with BasicConstraints CA=true, keyCertSign and cRLSign.
- A distinct, explicitly supplied **test root CA** with the same CA permissions (this root may be attacker-selected; it is **not** an approved FIDO root).
- Exactly **two** externally supplied DER-encoded X.509 **v2 full CRLs**: (1) an intermediate-**signed** CRL which covers the signer leaf, (2) a root-**signed** CRL which covers the intermediate. Each must be cryptographically signed by the actual issuer, fresh and unexpired, and must not contain the relevant revoked serial.

The certificate path is first built using .NET 10 `X509ChainTrustMode.CustomRootTrust`, `VerificationFlags=NoFlag`, no automatic certificate downloads, and an **exact three-element byte-for-byte match** against the provided leaf/intermediate/root chain. `X509RevocationMode.NoCheck` serves **only** to construct certificate signatures; separate explicit CRL checks enforce revocation of **both non-root certificates**.

Both CRLs are verified through the **same** internal BouncyCastle.Cryptography 2.7.0 DER parser/signature/issuer-binding/time/extension/revoked-serial code already used by the single-hop verifier introduced under #59. There are no parallel, differently implemented signature algorithms. The separate two-hop test fixture generates ephemeral RSA keys and certificates for root, intermediate and leaf and two real issuer-signed CRLs at runtime; no production trust anchor or private key enters source control.

The test matrix denies revoked leaf, revoked intermediate even with a nonrevoked leaf, wrong key for either CRL signature, swapped or missing one-hop CRL, mismatched/foreign root or intermediate, unsupported delta/indirect/unknown critical CRL extensions, missing `cRLSign` on either issuer, expired/future CRLs and expired certificates. Successful **cryptographic inspection only** returns:
- `ReviewStatus=UNAPPROVED`
- `PolicyStage=TWO_HOP_CRL_ONLY_ROOT_UNTRUSTED`
- SHA-256 digests of the two caller-supplied CRLs; no raw CRLs, certificates, signer key, trusted flag or ACTIVE key.

## Still release blocking (#57 / #55)

1. **Actual root trust:** the FIDO [MDS changelog](https://fidoalliance.org/mds-changelog/) records the August 2026 migration from GlobalSign R3 to **R46** and an R3→R46 `x5c[2]` transitional cross-certificate (R3/cross-cert expire **2029-03-18**). This regression uses arbitrary test root/intermediate values and does NOT prove the real R46 signing chain or 2026 x5c cross-cert interoperability. Approval and rotation of trust roots, explicit security review and offline root provisioning remain necessary.
2. **Actual revocation data:** no CRL distribution points, signed authenticated import, AKI, CDP scope, persistent CRLNumber rollback prevention, HSM-held root custody, delegated/indirect/delta CRL coverage, OCSP fallback or outage control are implemented. A caller could supply a **validly signed, currently dated but attacker-controlled/stale** CRL from an unapproved issuer. A cross-signed path may have a different number and order of certificates than this fixed test shape. The root is not revocation-checked independently as a trust anchor.
3. **Production status/enrollment:** a FIDO MDS JWT signature, attestation/model/AAGUID/firmware status and independent reviewer/registrar identity must be established and linked by a separate, audited trust adapter before any authorization. ADR 0029's JWS signature candidate and #56's metadata policy are **not connected** to this offline CRL verifier.
4. **Deployment/legal:** both on-prem OSS and Azure need the same fail-closed certified trust governance and secure network/offline update process; CAB/DPIA, independent human enrollment, signed challenge and atomic SQL decision remain blocked under #57/#55/#53/#44/#50/#46/#38. No qualified timestamp, eIDAS conformity, QTSP or WORM evidence claim follows from this slice.

See [ADR 0030](../adr/0030-offline-direct-issuer-crl-cryptographic-preflight.md), [offline direct-issuer CRL runbook](WEBAUTHN_MDS_OFFLINE_CRL.md), [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280), [RFC 10007](https://www.rfc-editor.org/rfc/rfc10007.html), and [BouncyCastle 2.7.0 tagged implementation](https://github.com/bcgit/bc-csharp/blob/release-2.7.0/crypto/src/x509/X509Crl.cs).
