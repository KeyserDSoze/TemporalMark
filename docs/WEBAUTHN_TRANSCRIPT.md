# WebAuthn untrusted signature transcript — operator and verifier boundary

Status: **test-only protocol-data foundation** (#43, ADR 0020). No approved WebAuthn signature flow is available in the standalone CLI, PWA or API.

The method `ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild` joins the **original** 37-byte basic-assertion `authenticatorData` to `SHA256(original clientDataJSON)`, yielding a fresh 69-byte untrusted message. It first applies the non-authorizing [client JSON](WEBAUTHN_CLIENT_DATA.md) and [authenticator data](WEBAUTHN_AUTHENTICATOR_DATA.md) checks with the strict independently pinned [RP/origin policy](WEBAUTHN_RP_POLICY.md). A passing result is **not a signature check**, and a malicious browser can fabricate both arrays and all their field values.

## Future verifier requirements — not implemented

1. Fetch the 48-byte V012 nonce, original request UUID/name/issuer/subjects/review SHA, action, rejection reason and expiry **only from the privileged database**, never by trusting client-provided scope. Verify original request remains pending and unexpired in the same decision transaction.
2. Require a separately and independently approved reviewer-held credential registration, exact identity issuer/subject and *currently effective* trusted IdP role + fresh MFA/ACR. An arbitrary supplied public key or self-registration is **not** a trust anchor.
3. Use a maintained audited WebAuthn/FIDO2 verifier that checks the browser's raw client JSON, RP ID, authenticator UV, approved credential ID and signature over original data, signCount and backup policy, and one-time nonce/action/scope binding. Candidate to assess: [fido2-net-lib (Fido2)](https://github.com/passwordless-lib/fido2-net-lib), stable v4.3.1 noted 2026-11-15. **It is not a dependency or deployed component today.**
4. Atomically consume one signed challenge and record terminal APPROVE or REJECT with nonsecret proof metadata, credential counter and current reviewer, and remove the previous direct `approve_enrollment`/`reject_enrollment` EXECUTE from reviewer SQL login as part of a reviewed cutover. Until that is done a stolen SQL credential can bypass signature checks.
5. Run end-to-end browser verification in disposable Keycloak OTP/PKCE + virtual authenticator CI with negative origin/action/replay/revocation/concurrent SQL tests; independently assess actual production device custody, recovery and legal WORM evidence. CI virtual key != independent real human consent.

## Deployment

- **On-prem:** use an approved HTTPS review host, independently configured RP ID and port, trusted IdP, secured verifier and credentials. No development localhost exception for production.
- **Azure:** pin the actual custom-domain review origin and secure IdP/credentials through approved services; never derive origin from forwarded headers or user-selected tenants. No production secrets or new signing keys added by this slice.
- No production `WEBAUTHN_*` setting, registration/assertion HTTP API or CLI `verify-signature` command exists. Do not expose the untrusted transcript as legal evidence or treat it as a signed decision.

## TDD

- RED test-first commit: `5f0291afd18369023d932eede1cf503aa7bb84da`.
- GREEN pure data method: `284bc49840a338b89a4b81291b34c48160365ef3`.
- ADR [0020](../adr/0020-webauthn-unsigned-signing-transcript.md).
- CI result and exact HEAD: record in [issue #43](https://github.com/KeyserDSoze/TemporalMark/issues/43), close only after backend, frontend, terraform, docker-smoke all green.

WebAuthn L3 §7.2: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-verifying-assertion. Parent #38/#35/#31 and independent WORM/QTSP #17/#13 stay open.
