# WebAuthn assertion client-data preflight (non-authorizing) — #41

**Not a signature verifier or an approval mechanism.** The .NET 10 `ReviewerWebAuthnClientDataPolicy` introduced after ADR 0018 is an unconnected parser/check for **attacker-controlled JSON**. It does not authenticate reviewers, register keys, consume challenges, authorize tenant creation or validate a WebAuthn assertion signature. No HTTP endpoint and no new SQL privilege exists. The older direct SQL reviewer approval/rejection path remains a production blocker under #38.

## Future trusted inputs (not current CLI/runtime config)

- Exact original `clientDataJSON` bytes returned by the browser, **not** a JSON object reconstructed in JavaScript or by the server.
- The original 48-byte nonce obtained **server side** from the specific unconsumed V012 database challenge, scoped to the pending request, intended action, reviewer identity, original digest and expiry; never from the browser-submitted `challenge`.
- The independently approved HTTPS origin/RP ID policy from [ADR 0017](../adr/0017-pinned-webauthn-rp-origin-policy.md), never from `Host`/`X-Forwarded-Host` or query values.

The parser requires `type=webauthn.get`, canonical unpadded base64url nonce, exactly pinned origin, no cross-origin iframe and no `topOrigin`. Unknown JSON fields and reordering are accepted; duplicate properties (even escaped aliases), invalid UTF-8, oversized/deep JSON, wrong field types and ambiguous encodings are denied. A UTF-8 BOM is allowed for parser compatibility **without modifying original bytes**.

When implementing #38, the maintained, audited verifier must independently validate the **cryptographic signature over authenticatorData concatenated with SHA256(original clientDataJSON bytes)**. It must validate registered credential ID/public key, exact `rpIdHash`, UV, challenge, expiry and one-time transaction consumption, signCount policy, current approved reviewer role and actual explicit reviewed human action. Database privileges must be cut over so a stolen approver SQL login cannot bypass verified signed consent. A passing parser check is **NEVER** a true assertion or authorization on its own.

## Deployment precautions

**On-prem:** Approve a real TLS FQDN and independent registration policy, never a localhost/IP shortcut for production. **Azure:** pin and own the exact public HTTPS origin and control reverse proxy trust; do not infer RP from tenant input or headers. Neither deployment currently has a WebAuthn assertion endpoint/credential store, and no `WEBAUTHN_*` configuration is supported. Browser virtual-authenticator fixtures are not evidence of independent hardware custody.

References: [ADR 0018](../adr/0018-webauthn-clientdata-preflight.md), [RP/origin guide](WEBAUTHN_RP_POLICY.md), [issue #38](https://github.com/KeyserDSoze/TemporalMark/issues/38), [W3C WebAuthn L3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/).

**Tests:** RED `c31c3a0`, GREEN `ea6c545`, extra JSON/BOM/base64url regressions `06c64f3`. Exact-head CI must be independently checked on GitHub before this child is closed.
