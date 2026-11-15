# ADR 0020 — Byte-exact, untrusted WebAuthn assertion transcript

Status: **accepted for non-authorizing transcript construction only** (2026-11-15). Child #43 of #38. Supersedes no prior decision; consult ADR 0016 (V012 challenge), ADR 0017 (pinned HTTPS origin/RP ID), ADR 0018 (raw `clientDataJSON` preflight), ADR 0019 (authenticator flags/preflight).

## Security problem

WebAuthn assertion signature verification operates over the **exact original** byte sequence `authenticatorData || SHA256(clientDataJSON)`. Re-encoding decoded JSON, normalizing UTF-8 BOM, using an origin/reviewer/nonce chosen by the browser, or hashing the wrong RP can cause signature mismatches or dangerous ambiguity. A reviewer may fabricate both input arrays and can pass **all structural preflights** without possessing any authenticator key. Thus a transcript is neither a signature nor a consent record. Independent approved credential binding, origin policy, UV, counter, live IdP role, human intent and atomic challenge consumption remain mandatory.

## Narrow decision

1. Add pure .NET 10 `ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild` that reuses the existing #41 and #42 untrusted preflight predicates. Caller must obtain the 48-byte expected nonce from the original unconsumed V012 database record and the RP policy from *server-approved* deployment settings, **never browser-originated data**. The method is not connected to an HTTP endpoint, a database action or the reviewer CLI.
2. Require both preflights to pass: original client JSON type `webauthn.get`, exact canonical unpadded base64url nonce, pinned HTTPS origin and top-level-only JSON semantics; strict 37-byte basic authenticatorData with exact SHA-256 RP hash, mandatory UP and UV flags, BE/BS consistency and no unsupported extension/attestation flags. These properties are *attacker-controlled claims* before signature verification. No authentication result is returned.
3. Construct a **new owned 69-byte** output buffer of the exact 37 original authenticator bytes, followed by SHA-256 of the **exact, unmodified original JSON bytes**. Retain UTF-8 BOM in the signed hash even though the JSON parser may omit it while interpreting fields. Never reserialize JSON, never append challenge/decision out-of-band, and never alias mutable input arrays in the returned buffer. On any failure return false with a null output; no partial messages.
4. TDD tests use independent Python-generated SHA-256 vectors for both the transcript and its hash, including a BOM vector; equivalent JSON with different member ordering produces a **different** transcript and is still structurally accepted. Negative cases cover RP, nonce, origin, flags, cross-origin, invalid UTF-8, wrong action, size and null input. RED contract `5f0291afd18369023d932eede1cf503aa7bb84da`, GREEN method `284bc49840a338b89a4b81291b34c48160365ef3`.
5. The preferred candidate for the future **real verifier**, pending security review, is the maintained MIT-licensed `Fido2` / fido2-net-lib v4.3.1 (latest stable found 2026-11-15), rather than inventing COSE/public-key/counter verification. **No package reference or verifier is added in #43.** It will require independently reviewed approved credential enrollment, persisted COSE key/signCount/BE state, precise `MakeAssertionAsync` API validation, configured origin/RP, original challenge in immutable trusted options, same-transaction one-use decision and revocation of old direct reviewer SQL approval/rejection EXECUTE. Never use this helper's output as verified evidence. Review library threat model, dependencies, patches, license, independent conformance and actual API before adopting it.

## Operational and legal stop-line

No WebAuthn credential registration/verification, human-held signature, explicit accept/reject UI, one-time assertion consumption, new SQL privilege or externally sealed audit is implemented here. A stolen reviewer SQL login can still invoke old direct decision functions; #38 must handle grant cutover **together with** verified signed approval. Neither CI fixtures nor an unsigned signing transcript establish independent human custody, legally sealed WORM, QTSP status or any qualified timestamp claim. Keep #38/#35/#31/#27, WORM #17 and legal #13 OPEN.

On-prem and Azure must independently pin a review HTTPS FQDN and port, protect privileged verifier/key registration and reviewer IdP trust, isolate non-public SQL roles, vault credentials and document credential loss/recovery before production. Never accept a client-selected RP, arbitrary public key or self-registration.

## Technical references

- W3C Web Authentication Level 3, Recommendation of 2026-08-25, §6.3.3/§7.2: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-verifying-assertion
- Maintained library candidate (not yet integrated): https://github.com/passwordless-lib/fido2-net-lib
- 4.x API migration guide: https://github.com/passwordless-lib/fido2-net-lib/blob/main/Documentation/migration-guide-4.0.0.md
- Stable package version listing: https://www.nuget.org/packages/Fido2
