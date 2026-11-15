# ADR 0019 — Untrusted WebAuthn authenticatorData structural preflight

Status: **accepted only for a non-authorizing basic-assertion guard**, 2026-11-15.
Child #42 of #38, following unsigned V012 challenge (#39), pinned RP/origin policy (#40/ADR 0017) and `clientDataJSON` preflight (#41/ADR 0018).

## Context

WebAuthn Level 3 §6.1 defines the authenticator-data binary layout: 32-byte SHA-256 `rpIdHash`, one flags byte, four-byte **unsigned big-endian** `signCount`, and optional attested credential and extension fields. Assertion verification §7.2 also requires checking RP hash, UP, user verification when requested, valid backup flags, then a **cryptographic signature using an independently registered credential public key**, counter/replay handling and current user binding. Without signature verification *every byte of authenticatorData is forgeable by the browser*. A matching RP hash or UV bit is **not proof that a physical authenticator verified a user**.

## Narrow decision

1. Introduce pure .NET 10 `ReviewerWebAuthnAuthenticatorDataPolicy.TryReadUntrustedAssertionData`, completely disconnected from HTTP endpoints, provisioning workflow, database writes and WebAuthn credential registration. Its only inputs are the original untrusted bytes and the **independently pinned** `ReviewerWebAuthnRelyingPartyPolicy`; it never accepts a browser-selected RP ID. Return a Boolean structural check and an untrusted `ReviewerAuthenticatorDataPreflight` snapshot containing counter and BE/BS flags, explicitly **not an authorization or verification result**.
2. Allow **exactly 37 bytes** for this initial strict basic-assertion profile: no trailing or truncated bytes, no attested credential data (`AT` must be 0 by specification), and **no extensions (`ED` must be 0 by local policy)**. Future support for signed extensions must use independently reviewed strict CBOR parsing, counter semantics and extension policies, not an optimistic parser.
3. Compute `SHA256(UTF8(server-pinned RP ID))` and compare to the first 32 bytes using `CryptographicOperations.FixedTimeEquals`. Require flags UP (0x01) AND UV (0x04), reject reserved bits RFU1/RFU2, AT and ED. Permit legal BE/BS combinations `00`, `10`, `11`; reject BS=1 with BE=0. An actually enforced UV policy is still pending credential-bound signature verification.
4. Read a big-endian unsigned 32-bit `signCount`, including the valid zero value, **without comparing, treating as signed, incrementing or persisting it**. The future signed verifier must compare to the independently stored last verified counter, evaluate zero-counter / multi-device / clone signals and synchronize counter changes with one-time challenge decision consumption under transaction control. W3C notes a counter anomaly is not definitive proof of cloning.
5. RED-first xUnit negative/positive contract in `tests/backend/TemporalMark.Business.Tests/ReviewerWebAuthnAuthenticatorDataPolicyTests.cs` (commit `785c6a2e29ea5f18fa13d80450c83869984e9487`) and GREEN isolated implementation `src/backend/business/TemporalMark.Business/Tenancy/ReviewerWebAuthnAuthenticatorDataPolicy.cs` (commit `1a87081084f462468fa94ff8e4eb672f60fd070a`). Tests cover RP mismatch, flag failures, invalid backup combinations, big-endian unsigned counters, zero counters, unsupported extension/AT bits, truncated/trailing data and null trusted policy. **Do not claim CI green without a four-job exact-head run.**

## Mandatory stop line and operations

- No WebAuthn assertion signature is checked, no registered reviewer credential/key/attestation trust store exists, no real approved WebAuthn UI/consent occurs, and **no challenge is consumed nor tenant approved or rejected**. Older restricted approver SQL routines remain callable directly and must be retired only together with the fully verified independent-signature transactional path (#38).
- Never treat `TryReadUntrustedAssertionData == true` or its `SignCount`/`BackupEligible`/`BackedUp` values as proof of possession, UV, a qualified decision, device custody or tamper-evident evidence. The helper does not store or log tokens, keys, credentials or raw authenticator assertions. Future verifier must validate a signature over the **original** `authenticatorData || SHA256(original clientDataJSON)` and link credential identity, signed challenge scope, decision/action and user review.
- On-prem/Azure/Entra production must independently govern RP domains, authenticator registration approval, key loss/rotation, per-credential counter policy, MFA, human custody, API/SQL least privilege and WORM evidence. Keep #38/#35/#31/#27 and legal #17/#13 OPEN.

## Primary technical source

W3C Web Authentication Level 3 Recommendation, 25 August 2026, [§6.1 Authenticator Data](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-authenticator-data) and [§7.2 Verifying an Authentication Assertion](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-verifying-assertion).
