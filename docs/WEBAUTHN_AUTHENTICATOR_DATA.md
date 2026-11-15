# Untrusted WebAuthn authenticatorData preflight (#42)

**No signed reviewer authorization is implemented.** The .NET 10 `ReviewerWebAuthnAuthenticatorDataPolicy` is a structural, unconnected guard. A malicious browser can forge *all* bytes that it parses. It cannot register or bind a credential, verify a signature, prove UP/UV, approve/reject an enrollment, consume a V012 challenge, or decide whether a credential counter is safe. The historical restricted SQL reviewer approval/rejection routines remain a production blocker (#38).

## Input and strict first-profile behavior

The future maintained signature verifier will receive the original `authenticatorData` as a **byte array** and a server-side preapproved HTTPS RP ID from [ADR 0017](../adr/0017-pinned-webauthn-rp-origin-policy.md). The parser checks only:
- Exactly 37 bytes (basic assertion, no attested credential data and no extensions). This deliberately excludes `AT` and `ED` binary flags, preventing unwanted CBOR/extension parsing for the first policy.
- 32-byte `rpIdHash` equals SHA-256 of the *pinned* ASCII RP ID, compared in fixed time. Never use an RP ID supplied in a request header, client property or tenant configuration unless independently authorized.
- Flags require **UP and UV**; reserved flags must be zero. BE/BS states are structurally checked: both false; BE true/BS false; BE true/BS true; but **not** BE false/BS true.
- Four-byte unsigned big-endian `signCount` is extracted, including valid zero values, and returned **solely as untrusted metadata**. Never use this parsed counter in account state updates without independently cryptographically validating the original data with the approved reviewer credential.

All relevant signatures, authenticators, keys and original data should be held at a separate privileged verification boundary. Parsing checks are necessary but *not sufficient*: a future verifier MUST validate signature over `original authenticatorData || SHA256(original clientDataJSON)`, original bound V012 nonce, type/origin, registered credential ID/public key, RP hash, UV, approved reviewer principal and current IdP role, counter + backup policy and challenge/decision transaction. Use a maintained audited library, not custom raw ECDSA/COSE/CBOR cryptography.

## Operations/deployment

**On-prem:** approve real TLS DNS RP/independently managed credential trust, enrollment, revocation, backup and device-loss process. **Azure:** pin the approved reviewer HTTPS host and independently hold signing enrollment/trust; no automated trust in forwarded headers, tenant or Entra claims alone. No present `WEBAUTHN_*` environment variable or HTTP/WebAuthn assertion endpoint is operational; do not attempt to enable a signed workflow by adding a configuration value. A CI virtual authenticator, if introduced, is a functional test fixture, not evidence of independent human/device custody.

## TDD and closure conditions

- RED `785c6a2e29ea5f18fa13d80450c83869984e9487`: tests added before policy existed.
- GREEN `1a87081084f462468fa94ff8e4eb672f60fd070a`: strict 37-byte unsigned preflight and parsed counter/BE/BS metadata.
- [ADR 0019](../adr/0019-webauthn-authenticator-data-preflight.md), [threat model](THREAT_MODEL.md), [original client data guide](WEBAUTHN_CLIENT_DATA.md) and [issue #38](https://github.com/KeyserDSoze/TemporalMark/issues/38).

**Keep #42 OPEN until exact final main commit has backend, frontend, Terraform and docker-smoke CI all GREEN.** Keep #38, #35, #31, #27, #17 and #13 OPEN irrespective of isolated preflight test success.

W3C primary source: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-authenticator-data
