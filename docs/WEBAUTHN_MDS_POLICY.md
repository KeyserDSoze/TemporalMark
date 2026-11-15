# WebAuthn FIDO MDS policy inspection — **UNAPPROVED ONLY** (#56)

**Not a production MDS trust service.** This runbook documents a narrow, isolated .NET 10 metadata-policy preflight. It does **not** download or validate any FIDO MDS signed BLOB, perform signed-JWS chain validation, trust attestation certificate paths, authorize enrollment, store credentials or re-enable database decisions. The WebAuthn registrar's V015/V016 SQL interlock and CLI suspension are **unchanged**. Parent issues [#55](https://github.com/KeyserDSoze/TemporalMark/issues/55), [#53](https://github.com/KeyserDSoze/TemporalMark/issues/53), [#44](https://github.com/KeyserDSoze/TemporalMark/issues/44), [#50](https://github.com/KeyserDSoze/TemporalMark/issues/50), [#46](https://github.com/KeyserDSoze/TemporalMark/issues/46) and [#38](https://github.com/KeyserDSoze/TemporalMark/issues/38) remain open.

## Scope and exact behavior

`src/backend/infrastructures/TemporalMark.Infrastructure/WebAuthn/ReviewerMdsMetadataPolicyPreflight.cs` uses the exact pinned Fido2 **4.3.3** public metadata model classes. It is a pure, deterministic, **non-authorizing** inspection: no HTTP client, no Keycloak, no SQL, no Azure or other runtime dependency. It accepts an *untrusted in-memory* `MetadataBLOBPayload` object and pre-existing *untrusted* candidate metadata, never an unverified JSON string promoted to production trust.

The inspector can return only `ReviewStatus=UNAPPROVED`, `PolicyStage=MDS_METADATA_INSPECTION_ONLY`, candidate AAGUID and supplied BLOB serial; **it cannot return a signer, key, certificate, attestation-chain proof, trusted bit, new membership or ACTIVE credential**. Even an apparently valid observation is merely a unit-testable policy shape check. It rejects:
- Missing or non-`UNAPPROVED` `packed` / `attca` candidate, empty AAGUID, malformed SHA-256 hashes, backup-eligible or backed-up/synced keys.
- No metadata, no entry matching the candidate AAGUID, duplicate exact AAGUID, entry/metadata-statement identity mismatch, non-FIDO2 protocol or unsupported schema/attestation type.
- Missing or malformed encoded X.509 v3 `attestationRootCertificates`, too many roots or oversized certificate data. **Parsing a certificate does NOT verify its chain**; per FIDO Metadata Statement, a valid trust anchor may be a root, intermediate or even a leaf.
- Any security report other than explicitly enumerated `FIDO_CERTIFIED_L2`, `L2plus`, `L3` and `L3plus`. In particular, the presence of any `REVOKED`, `USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`, `USER_KEY_REMOTE_COMPROMISE`, `USER_KEY_PHYSICAL_COMPROMISE`, `RETIRED`, `UPDATE_AVAILABLE`, or unknown status denies **even alongside** a certification report. This conservative proposed policy can reject valid real devices and must not be described as CAB-approved.
- Missing/invalid serial, serial smaller than the supplied minimum, observation older than 24 hours or in the future, and an explicitly supplied malformed/elapsed ISO `nextUpdate`. `nextUpdate` is not treated as sole freshness: the latest FIDO MDS 3.1.1 guidance discourages depending on it, and it may be removed. The **caller-supplied** timestamp and serial minimum are not independently authenticated, durable anti-rollback evidence.
- Rogue-list URL/hash, because this slice has no verified rogue-list downloader.

Tests in `tests/backend/TemporalMark.Provisioner.Tests/ReviewerMdsMetadataPolicyPreflightTests.cs` use **synthetic unsigned models and a disposable test certificate**, never a real MDS JWT/physical attestor. They prove only policy behavior and adversarial rejection.

## Critical current root-rollover / revocation gap (not solved)

FIDO's official [MDS changelog](https://fidoalliance.org/mds-changelog/) reports a change from **GlobalSign Root CA R3 to Root R46 in August 2026**. An R3→R46 cross-certificate has appeared in `JWT x5c[2]` since **2026-08-31**, but R3 and the cross-certificate expire **2029-03-18**. An approved production verifier must manage and pin R46 before that deadline. The Fido2 **4.3.3** tagged `Fido2MetadataServiceRepository` still embeds an **R3** certificate; its `DeserializeAndValidateBlobAsync` uses `X509RevocationMode.NoCheck` on one host-trusted chain path and a separate custom CRL path for an untrusted root. **Do not infer universal certificate revocation enforcement merely from successful JWT validation.** Production must independently audit and test both code paths, FIDO R46 rollover, CRL validity, offline behavior and SSRF controls; no unsafe bypass or demo-root trust.

The genuine MDS BLOB JWT has JWS signature and `x5c` chain; the application must use a maintained verified library or a separately audited provider to validate it against independently pinned roots and CRLs. Add immutable, shared monotonic BLOB serial/digest evidence and reject rollback or same-serial divergence; preserve latest status and status time, decide key-model allowlists with CAB/security counsel, verify attestation-leaf chain against the metadata **model-specific** roots, and block if trust metadata/CRLs are unavailable, stale, revoked, unknown or ambiguous.

## Environment and governance requirements

Both on-prem and Azure must apply the *same* policy. On-prem offline/air-gapped sites need independently transferred, verifiably signed and fresh MDS BLOB plus CRLs and administrator-approved root rotation. Azure requires similarly isolated network egress, certificate path and revocation monitoring; neither deployment may silently accept stale cache or trust the host CA store alone. Do not log raw attestation certificates, device serials, key bytes or PII; perform DPIA and retention/erasure analysis before any production registration. CAB/security approval and independent key-custody ceremony remain mandatory.

This slice has **no material changes** to PostgreSQL migrations, JWT/OIDC, Keycloak, TSU/HSM, timestamp issuance, WORM retention or legal qualification. It does not claim a qualified electronic timestamp service. See [ADR 0028](../adr/0028-fail-closed-non-authorizing-mds-metadata-policy.md) and [ADR 0027](../adr/0027-packed-attestation-real-library-fixture-and-mds-trust-boundary.md).

### Primary technical references

- [FIDO MDS changelog](https://fidoalliance.org/mds-changelog/)
- [FIDO MDS 3.1](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html)
- [FIDO Metadata Statement 3.1.1](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html)
- [Fido2 4.3.3 metadata repository source](https://github.com/passwordless-lib/fido2-net-lib/blob/4.3.3/Src/Fido2/Metadata/Fido2MetadataServiceRepository.cs)


## Cryptographic JWS test-only extension (#58)

The [signed-JWS precheck runbook](WEBAUTHN_MDS_JWS_PRECHECK.md) records a new **separate, non-authorizing** offline RS256 signature/X.509 test-path verifier, built under ADR 0029 with real Microsoft.IdentityModel JWT signature checks and ephemeral RSA test CA. It does not pass verified MDS models into this policy inspector; there is no signed/CRL-validated producer for the metadata policy. `X509RevocationMode.NoCheck` in that isolated candidate means **all results remain UNAPPROVED** and production trust is still blocked by #57/#55, including R46, revocation, immutable serial and independent attestation chain governance. V015/V016 remain unchanged.
