# Fido2 4.3.3 — isolated WebAuthn attestation candidate verifier (#52)

**Current status: CANDIDATE ONLY. Not registered, approved, ACTIVE, attested as trusted hardware, or authorized for tenant decisions.** The V015/V016 SQL registrar issuance freeze and the former `registrar-intent` CLI suspension remain strictly in force. See [ADR 0026](../adr/0026-fido2-registration-candidate-verifier.md), [#44](https://github.com/KeyserDSoze/TemporalMark/issues/44), [#50](https://github.com/KeyserDSoze/TemporalMark/issues/50) and [#38](https://github.com/KeyserDSoze/TemporalMark/issues/38).

## Dependency and exact library surface

The infrastructure project pins NuGet `Fido2` **4.3.3** (MIT, stable, released 2026-11-11; .NET 10 compatible). It uses the published version's `IFido2.MakeNewCredentialAsync(MakeNewCredentialParams)` interface, **not** the preview or the upstream `main` APIs: 4.3.3 does not expose `Fido2Configuration.Validate()`, `MakeNewCredentialParams.Mediation` or `RegisteredPublicKeyCredential.RpId`. The strict `ReviewerWebAuthnRelyingPartyPolicy` independently pins the exact canonical HTTPS origin and matching RP ID; the stable library checks the authenticator RP ID against its configured RPID. The `Fido2` instance is configured without a Metadata Service/trust anchors. There is no new dependency on Azure or proprietary servers.

Use of stable verifier does not solve device provenance by itself. The library accepts registration of `none` and `self` attestation under some valid WebAuthn flows; these are **denied** by TemporalMark's candidate policy, rather than conflated with independent attestation. Even library-verified `basic`, `attca`, or `anonca` results remain **UNAPPROVED** until verified against independently approved trusted metadata and signer/device governance.

## Exact current behavior

The isolated `ReviewerRegistrationAttestationCandidateVerifier` lives in `src/backend/infrastructures/TemporalMark.Infrastructure/WebAuthn/`. It has no API/PWA/CLI or PostgreSQL caller and cannot write any credential or mutate a tenant.

A future trusted internal caller must obtain a **server-side original** ceremony record with a 48-byte nonce, opaque 32-byte reviewer handle, expected issuer/reviewer/independent registrar subject and 120-second maximum lifetime; the corresponding original `CredentialCreateOptions` must demand `UserVerification=Required` and direct/enterprise attestation. The caller must also supply a REAL globally unique credential-ID callback backed by a later approved credential registry, never a blanket true callback. Until that registry, originally issued server-side registration options and signed two-human registrar approval are implemented, this is a **cryptographic verification component**, not a completed registration workflow.

The component checks exact challenge equality, RP ID, original user handle, expiry, independent role-actor subjects, credential ID encoding/length, raw attestation/clientData length limits and required UV **before** calling the maintained library. The library parses and verifies original WebAuthn registration data (with cryptographic checks). Even after library return, identity binding, allowed attestation type, credential ID, user handle, original RP scope and public-key bounds are rechecked. Only a hash of the credential ID, a hash of the verified public key, type, format, AAGUID and backup/counter metadata escape, with status **`UNAPPROVED`**; raw public-key bytes are not exposed and no persistent credential is created.

Security footnotes: A scoped result is **not** proof of human consent or trusted attestation provenance. Neither a hash nor the FIDO authenticator counter provides replay-safe one-time database commitment; `SignCount=0` is normal for some authenticators. The injectable `IFido2` and global-unique callback are future trust boundaries requiring production implementation/testing. Unit tests simulating a successful `IFido2` result **do not prove a real authenticator succeeded**.

## Verified test coverage and next mandatory steps

xUnit tests first appeared before code and failed without the adapter/dependency. After pinning 4.3.3, tests cover wrong/short/mutated challenge, RP mismatch, malformed/oversized `rawId`, bogus client data and CBOR passed to the **real stable Fido2 verifier** (it must reject), expired/future/non-independent identity scope, weak UV, missing attestation, `none/self/unknown` type and mismatched credential/user handles. The mock-positive test verifies only the `UNAPPROVED` hash-only result and library delegation.

The release must still implement: trusted, independently approved two-person registrar and reviewer identity/consent bound to a **consumed** original nonce; production attestation metadata trust chain, policy and human device custody; globally unique ACTIVE key/COSE public key registry and revoke/recovery with transactional locking; browser `navigator.credentials.create()` positive+negative realistic hardware or virtual-authenticator fixtures; safe independent audited SQL activation with no alternative direct grant; subsequent `MakeAssertionAsync` plus original action signature and old SQL approval grant cutover; WORM/eIDAS/AgID/CAB/QTSP compliance.

**The SQL V015/V016 stop-line must remain intact**. Do not undo migration permissions or use an arbitrary candidate hash to activate any credential. This component is strictly preparation for #44/#50/#46, not completion of their acceptance.

## Sources

[Fido2 4.3.3 NuGet](https://www.nuget.org/packages/Fido2/4.3.3), [Fido2 tagged source](https://github.com/passwordless-lib/fido2-net-lib/tree/4.3.3), [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/), [ADR 0026](../adr/0026-fido2-registration-candidate-verifier.md).
