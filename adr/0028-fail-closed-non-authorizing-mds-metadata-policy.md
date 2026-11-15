# ADR 0028 — Fail-closed WebAuthn MDS metadata policy inspection is never signer trust

Status: **accepted only for non-authorizing metadata policy checks**, 2026-11-15. Issue #56 focused child of #55/#53, after #54 and ADR 0025–0027. Parent #44/#50/#46/#38 and the V015/V016 SQL freeze remain OPEN.

## Background: exact stable library + current official metadata

The pinned **Fido2 4.3.3** NuGet provides `MetadataBLOBPayload`, `MetadataBLOBPayloadEntry`, `MetadataStatement`, `AuthenticatorStatus`, `IMetadataRepository` and `Fido2MetadataServiceRepository`. The upstream tagged repository validates an MDS JWT signature and chains certificates to a hardcoded **GlobalSign Root R3**. Its implementation has distinct certificate-revocation paths, including a `X509RevocationMode.NoCheck` branch for a chain trusted by the system and custom CRL checking only in an alternate path. **Do not claim this independently passes a production CAB revocation audit** or that an arbitrary C# object is verified MDS evidence.

The FIDO MDS **August 2026** root changed from GlobalSign R3 to **R46**, with an **R3→R46 cross-certificate** in `x5c[2]` added August 31, 2026 for transition. FIDO explicitly requires planning R46 trust before **March 18, 2029**; R3-only pinning is not a permanent solution. The FIDO 3.1.1 specification also discourages reliance on `nextUpdate` as the only freshness signal because that field is intended for removal. These release/security differences are a **blocker for independent future approval**, not something this metadata field preflight silently fixes.

## Deliberately narrow decision

1. Build a pure, deterministic **inspection-only** `ReviewerMdsMetadataPolicyPreflight` in infrastructure, no API, CLI, SQL, network, MDS fetch, registration or attestation trust root configuration. Its input `MetadataBLOBPayload` and candidate may be forged by callers and are **explicitly untrusted**. Only a later independently reviewed signed-BLOB/chain/CRL adapter and persistent monotonic cache can supply production provenance. No application authorization code may consume this inspection as permission.
2. Reject all but exact hash-only `UNAPPROVED` `packed`/`attca` candidate with 64-character uppercase SHA-256 hex digests and nonempty AAGUID; invalid/duplicate/missing matching AAGUID entries or mismatch between entry and metadata statement, unsupported schema/protocol/attestation type; absent/malformed/too-many/oversized attestation trust-anchor certificates (parsing only, **not validation**). No unknown or mixed security status may pass.
3. Conservative, **test-only high-assurance proposed profile**: only explicit `FIDO_CERTIFIED_L2`, `L2plus`, `L3`, `L3plus` reports can pass; reject any `REVOKED`, `USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`, `USER_KEY_*_COMPROMISE`, `RETIRED`, `UPDATE_AVAILABLE`, `NOT_FIDO_CERTIFIED`, `SELF_ASSERTION_SUBMITTED` or unrecognized/undefined enum, even if a different certified report also appears. This is intentionally stricter than normal MDS status interpretation and may reject real devices. The policy needs independent organizational approval before it can become operational.
4. A supplied UTC observation timestamp must be no older than 24 hours and not in the future; nonpositive snapshot serial or serial below the **caller-provided** minimum is rejected. `nextUpdate` is treated conservatively when present (ISO date today or later); omission is tolerated only under the separate 24-hour observation cap to account for 3.1.1 deprecation. **Neither an observation timestamp nor a caller-provided minimum proves a signed immutable checkpoint**, so positive policy inspection remains `UNAPPROVED`.
5. Return **only a non-authorizing observation** with `UNAPPROVED`, AAGUID, metadata serial, and policy label. No `TRUSTED`/`ACTIVE` state, no signing certificate, accepted public key, attestation/CRL proof or credential store path. No deployment may treat it as FIDO certification evidence or as sufficient for admission.
6. RED tests on `main` before GREEN implementation, including adversarial statuses, corrupted trust anchor, replay/rollback, timestamp and matching AAGUID cases. Four-job final-head GitHub CI required for child #56 closure. Keep #55 OPEN for **real signed BLOB x5c/JWS, root R46 migration, mandatory revocation evidence, AAGUID certificate-path verification, cross-region/air-gap refresh, persisted monotonic serial, outage/rollback tests, privacy/DPIA**; #53 and #44/#50/#46/#38 also stay OPEN.

## On-prem/Azure policy and hard stop

Exactly the same non-authorizing offline policy is compiled for both deployments. No Azure mandatory dependency, FIDO trust roots provisioned, CRL bypass, demo CA trust, role/grant change, or attestation signer enrollment. No secrets or per-device serials logged. Production signing root distribution/rotation and CRL proxies (including a safe network policy for offline installations), immutable signed checkpoint and security/privacy approval belong to #55. V015/V016 stop line and existing suspended registrar CLI **remain intact**. No qualification/WORM claims.

References:
- FIDO MDS changelog, 2026 August/September: https://fidoalliance.org/mds-changelog/
- FIDO MDS 3.1: https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1-ps-20250521.html
- FIDO Metadata Statement 3.1.1: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html
- Fido2 tagged 4.3.3 source: https://github.com/passwordless-lib/fido2-net-lib/blob/4.3.3/Src/Fido2/Metadata/Fido2MetadataServiceRepository.cs
- ADR 0027: [Test-only packed attestations](0027-packed-attestation-real-library-fixture-and-mds-trust-boundary.md)
