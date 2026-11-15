# ADR 0018 — WebAuthn clientDataJSON validation-only assertion preflight

Status: **accepted as a non-authorizing protocol-data guard only**, 2026-11-15.
Child #41 of #38; follows V012/ADR 0016 (#39) and ADR 0017 (#40). No production verifier is implied.

## Context

WebAuthn Level 3 assertion verification compares `CollectedClientData.type`, challenge and origin (and rejects unsupported cross-origin framing) before relying on a cryptographically verified signature. An attacker can construct the entire `clientDataJSON` without an authenticator. Therefore accepting these strings by itself provides **zero proof of a registered credential, consent, or a signed decision**. A separate audited verifier must validate the signature over authenticator data and the SHA-256 of the **original, unmodified** client data bytes, alongside key registration, `rpIdHash`, UV, counter and atomic consumed challenge.

## Narrow decision

1. Provide `ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData` in the .NET 10 business layer **without any API, CLI, SQL or authentication integration**. It accepts only original raw JSON bytes, a **48-byte V012 nonce supplied by a trusted server-side store**, and the separately pinned `ReviewerWebAuthnRelyingPartyPolicy` from ADR 0017. It returns only a Boolean negative precondition; it cannot approve, reject, consume a challenge or attest a signature.
2. Require exact `type=webauthn.get`, exact unpadded base64url encoding of the trusted server nonce, exact origin from the pinned HTTPS policy. No `webauthn.create` or wildcard/suffix/host-header origin is accepted. This is intentionally a **top-level-only** profile: `crossOrigin` may be missing or JSON `false`, but `true` or a wrong type fails. **Any** `topOrigin` fails, including when `crossOrigin=false`. Supporting iframe/related-origin requests requires independent policy and security review.
3. Permit JSON members in any order, optional unknown members and a UTF-8 BOM as WebAuthn specifies; reject duplicate member names, including encoded Unicode aliases, to eliminate parser ambiguity. Bound payload to 4,096 bytes and JSON nesting depth to 8; forbid malformed UTF-8, JSON comments, trailing content/commas and malformed mandatory field types. This is a deliberately restrictive production policy that might exclude extensions/deep vendor payloads; security review before loosening.
4. Never reserialize or normalize the signed JSON bytes: a future verifier must hash the exact `clientDataJSON` bytes received, not the parsed object, even if a BOM was stripped for parsing. No credential IDs, signatures, public keys, user handles, JWTs or OTP are stored or logged by this helper. The expected nonce is never to come from the browser's `challenge` string.
5. RED-first xUnit contract `c31c3a0792ba0f029bac5fe089dad8ab320ec18c` and GREEN implementation `ea6c5459822acf0c9a1d676440f1428f863dd65e`. Follow-up regression `06c64f3cb8fc1449a3e4dd7c6f53a0429892dca1` covers '+'/'/' base64url conversion and byte-preserving UTF-8 BOM handling. Tests are not a signed WebAuthn integration or a verified CI success until the exact-head four-job run completes.

## Mandatory trust boundary / future work

- **No runtime verifier, registered/approved reviewer key, authenticated user presence/verification (UP/UV), signed authenticator data, signature, `rpIdHash`, signCount or signature-bound decision exists.**
- No new registration/assertion endpoint, SQL grants, terminal decision, challenge consumption or PWA signing UX is implemented. Older approver SQL roles can still bypass any unsigned client preflight by executing direct SQL decision routines; #38 must remove/restrict that route atomically with an independently governed signature verifier. Absolutely no use of `MatchesUntrustedClientData == true` as an authorization permit.
- CI virtual authenticators or Keycloak OTP fixtures do not prove separate real human custody, production MFA policy, WORM evidence or legal QTSP qualification. Keep #38/#35/#31/#27/#17/#13 open.
- Production on-prem/Azure/Entra must pin HTTPS RP origin, manage registered reviewer keys under independent oversight, validate signed challenges with a maintained verifier library, reconcile identity revocation and handle key rotation/loss before claim of working WebAuthn approval.

## Normative reference

W3C Web Authentication Level 3 Recommendation (2026-08-25), particularly §5.8.1 `CollectedClientData` and assertion-verification checks: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/ .
