# Initial security threat model

Assets: TSU signing keys, real-time clock measurements, immutable timestamp tokens, evidence manifests, tenant identities, role grants, backups and customer imprint hashes.

Trust boundaries: internet → gateway; gateway → OIDC; API → tenant-scoped DB; API → object store; TSU → HSM; TSU → time authority; production → administrative control plane. Keys and trusted time must not be available via ordinary application admin actions.

Priority abuse cases and required controls:
- Tenant A reads/export Tenant B: cryptographically validated tenant membership, query isolation, RLS, cross-tenant tests, structured audit.
- Last tenant administrator removed: transactional invariant and concurrency tests; platform recovery with four-eyes authorization.
- Forged/misattributed timestamp: strict RFC 3161, response signature/certificate/nonce/algorithm checks, historical Trusted List validation.
- Untrusted or drifting clock: measured UTC(k) traceability, active time-health monitor and immediate failure-closed service state.
- HSM key compromised or expired: immediate suspension and incident window/serial identification.
- Audit log/evidence edited or erased: WORM store, hash chains, manifest signatures, independent backup/restore and evidence reconciler.
- Exfiltration via export: role-specific authorization, bounded period, request limits, job auditing, export encryption and expiry.
- Credential theft, SSRF in external TSA URL, supply chain vulnerabilities: secret management, allowlisted static egress, signing and SCA, minimal privileges.

This is a starting list; run a structured STRIDE/LINDDUN workshop and DPIA assessment prior to production.

## Database tenancy integrity addendum (#22)

Concurrent membership revocation/demotion and creation of empty active organizations are tested against PostgreSQL 17 using deferred constraint triggers and parent-row version updates. Repeatable Read/Serializable writers may receive SQLSTATE `40001` and must retry entire transactions. A schema owner may disable triggers, so production schema/data roles must be separated and controlled. Privileged bootstrap has no public HTTP exposure but currently depends on an **out-of-band verified OIDC subject**; human process and identity reconciliation are not equivalent to automated proof. See [ADR 0006](../adr/0006-tenant-bootstrap-and-admin-integrity.md). Additional risks: unauthorized provisioning-role grant, forged `sub`, identity reassignment, migration-role compromise, and absence of DB RLS/privileged audit.

## OIDC operator provisioning addendum (#24)
Separate signed OIDC access tokens from the same pinned issuer are verified against intended audiences, `platform_provisioner` and `tenant_admin` roles, signature/algorithm, expiry and five-minute issuance freshness before privileged organization bootstrap. The operator tool has no public HTTP entry point, uses owner-only token files and a separate PostgreSQL login; `V004` stores irreversible token hashes with unique constraints for single use. **Residual risks:** an access token can be revoked while its signature/expiry remain valid; database-provisioner credential theft can bypass the independent JWT checks; there is no MFA step-up approval, automated IdP claim synchronization, independent WORM audit or multi-issuer membership key. See ADR 0007 and #23.

## Live-token status prior to provisioning (#26)
Both signed operator/first-admin access tokens now undergo a fresh Keycloak RFC7662 confidential-client introspection check before DB bootstrap; no positive status caching, redirect following, untrusted IdP URL or offline fallback. Fail closed on disabled/revoked token or provider outage. **Residual:** a token's returned role may be an issuance-time snapshot, the account may change after introspection (TOCTOU), and a compromised provisioner SQL login bypasses application-layer checks. There is no separate live directory-role reconciliation, independent approval ceremony, Entra adapter or sealed audit yet (#25/#23).

## Independent approval gate (pilot, #29)

PostgreSQL V006/V007 now requires a pending request bound to issuer, exact organization name, operator/admin subjects and generated organization UUID, a third separately authenticated Keycloak `platform_approver` role and distinct SQL login, and an atomic approval consumption during organization+audit creation. The pending request expires after five minutes. Threats still outstanding: stolen approver bearer credential/DB login can simulate approval, no MFA/step-up or certified independent human signoff, privilege escalation via migration owner, token-state TOCTOU, unenforced identity-account role changes, unsealed approval evidence. See ADR 0009 and #27; not legally qualified.

## Current Keycloak account/role gate (#30)

The operator CLI now independently queries Keycloak user.enabled and effective realm-role mappings after cryptographically checking the signed JWT and Keycloak live token state; this rejects removed roles or disabled accounts even if issued JWTs still carry old entitlements. A dedicated confidential service account uses read-only realm-management permissions (CI-only grants). Outages, malformed data, 403, identity mismatch and stale authorization fail closed. **Residual:** race between IdP query and DB commit, compromise of directory client credentials, privilege-scoping drift, approval token theft, no MFA/step-up evidence, no directory signed response/WORM and no Entra adapter. See ADR 0010, #27, #28; still not qualified.

## ACR / authentication freshness for approvers (#32)

The standalone CLI now requires a policy-pinned `acr` and recent `auth_time` read only from a cryptographically verified access token; password-only/weak, missing or stale values are rejected **before** consulting Keycloak current role state or granting SQL approval. The disposable password-grant CI realm has a strictly scoped non-MFA exception to preserve other integration tests; it does not test or guarantee a second factor. An arbitrary ACR configured in the IdP might still misrepresent its real authentication flow: actual MFA ceremony and independent human confirmation remain #31. A stolen high-assurance bearer token, service credential, SQL approver login, IdP-to-DB race or missing sealed evidence still threaten enrollment. ADR 0011 applies; not QTSP-qualified.

## Approval assurance provenance (#33)

The pilot now stores only signed OIDC ACR/auth_time assertions and policy IDs, clearly distinct from an explicitly **non-MFA** local password-grant fixture and `LEGACY_UNVERIFIED` historic approvals. The restricted SQL approver cannot invoke the old proof-free function; unconsumed legacy approvals cannot activate tenants. A privileged SQL account can still forge metadata, and the IdP may misconfigure ACR without actually requiring two factors. Neither the audit record nor tokens are independently sealed. See ADR 0012, #31 (real MFA), #17 (WORM).

## Real Keycloak OTP/PKCE integration-test boundary (#34)

Disposable CI now configures a distinct Keycloak realm with conditional LoA1 password and LoA2 OTP, no SSO-cookie bypass, and explicit ACR mapping. A Playwright browser first registers OTP (not counted as MFA), then reauthenticates in a clean session, verifies incorrect OTP denial and correct OTP acceptance, exchanges an OIDC code using PKCE, checks real Keycloak JWKS-signed `acr` and fresh `auth_time`, and calls the strict .NET validation path without the password-only local exception. The **same automated CI job holds the OTP secret and password**, so this is a functional second-factor-flow regression, not independent human factor possession, production compliance, a certified human four-eyes decision or tamper-evident evidence. The CI realm uses demo credentials and must never be copied into on-prem/Azure production topology. See ADR 0013, #31, #17, #28.

## Reviewer original-scope review (V009, #36)

The restricted reviewer-only SQL routine reads only one unexpired and unapproved request after current signed OIDC role/token/ACR checks. The CLI shows DB-fetched legal name, issuer, actors and expiry and requires a canonical, fixed-time-compared SHA-256 instead of operator-copied fields. Wrong digest, expired/approved request, actor-self-review and direct SQL SELECT are denied. The hash is NOT a reviewer signature; a compromised DB approver login may still call the legacy 10-argument function without review, and a database owner can modify audit. Signed challenge-bound accept/reject, witnessed consent, actual production human MFA and WORM remain #35/#31/#17. ADR 0014.

## One-time reviewer rejection (V010, #37)

V010 adds terminal approved-versus-rejected integrity constraints; a rejected request is never visible as pending and cannot be approved or completed through the legacy SQL routine. The reviewer-only `reject` CLI checks original-scope SHA, signed OIDC/ACR, live token status, current role and a bounded decision reason. Postgres records an audit subject/time, reviewed digest and one-way token SHA; a shared UNIQUE decision ledger prevents the same token being reused across approve and reject, and concurrent decisions serialize on the pending row. **Residual:** authorized SQL approver credentials can invoke the decision routine directly without proof of witnessed human signature, and a migration owner can override records. This is not independently sealed/WORM proof. Complete reviewer-held challenge/FIDO2 signing, actual witnessed consent and production IAM in #35; ADR 0015.

## SQL CHECK three-valued logic on terminal rejects (V011, #37)

An otherwise valid `rejected_utc` transition may evaluate a nullable regular-expression/allowlist predicate as UNKNOWN, and PostgreSQL `CHECK` accepts UNKNOWN. V011 adds strict `IS NOT NULL` requirements for rejected reviewer subject, token proof, reviewed scope digest and fixed reason. Owner-level direct-update regression tests prove that incomplete terminal decisions are denied even before the audit trigger. Historical migrations are not rewritten. This constraint does not make ordinary PostgreSQL audit WORM or protect against a schema owner disabling constraints. See ADR 0015 and #17.

## WebAuthn challenge foundation (#39)

A short-lived DB-generated, unpredictable nonce is bound to the original pending request and the current, signed/live/reviewed approver identity plus decision type, reason and expiry. The challenge itself has no power to APPROVE or REJECT; no signature is checked and it is not consumable. The old approver SQL login remains a bypass to human-signed decisions, so FIDO2 credential binding, verified RP/origin/UV/signature/signCount, transactional consumption and privilege removal remain #38. Migration owner can alter the pilot DB; it is not WORM or a QTSP certification. ADR 0016.

## Strict WebAuthn relying-party origin profile (#40, ADR 0017)

A future browser verifier must NEVER derive the trusted WebAuthn RP ID or origin from a request `Host`/`X-Forwarded-Host`, CLI argument, browser-provided field or bearer token. Origin confusion (HTTP downgrade, attacker-controlled subdomain or prefix, wildcard, userinfo, port confusion, IDN lookalike) could bind an authenticator assertion to a different relying party. The validation-only `ReviewerWebAuthnRelyingPartyPolicy` pins a canonical HTTPS DNS origin and exact matching RP ID from independently approved server settings and rejects these cases under unit tests. It is deliberately stricter than the general registrable-domain suffix option. It is **not currently wired into a verifier**; no verified signed assertion or user consent exists. Production must separately verify `clientDataJSON`, signed `authenticatorData`/`rpIdHash`, UV, enrolled key/signCount, atomic nonce consumption, current role and reviewer-held human action. SQL approval/rejection bypass remains until #38. This is not WORM or QTSP qualification. See [ADR 0017](../adr/0017-pinned-webauthn-rp-origin-policy.md) and [deployment checklist](WEBAUTHN_RP_POLICY.md).

## WebAuthn clientDataJSON ambiguity and iframe preflight (#41, ADR 0018)

The browser-provided `clientDataJSON` is **fully attacker-controlled until a real registered reviewer-held key signature is verified**. The validation-only .NET preflight checks exact type, server nonce base64url, pinned HTTPS origin, forbids cross-origin iframe/topOrigin, duplicate member names and malformed/oversized/non-UTF-8 JSON. It preserves original bytes for future SHA-256 signature verification. Unknown JSON keys/order remain accepted for WebAuthn compatibility. A positive preflight result **never authorizes approval/rejection**, and the older approver SQL decision routines still allow unsigned bypass (#38). A stolen SQL role and unverified authenticator assertions remain critical production threats. Future reviewer-held key enrollment, UV, RP hash, user/account reconciliation, signed human action, transactional challenge consumption and removal of old grants are mandatory; no WORM/QTSP claim. [ADR 0018](../adr/0018-webauthn-clientdata-preflight.md), [deployment guidance](WEBAUTHN_CLIENT_DATA.md).

## Untrusted authenticatorData acceptance boundary (#42; ADR 0019)

A malicious browser can forge `authenticatorData` including RP SHA-256 hash, UP/UV bits, BE/BS flags and the counter unless an independently enrolled reviewer-held credential's **signature is verified**. The new validation-only .NET 10 preflight rejects wrong RP hash (constant time), missing UP/UV, reserved flags, illegal BS without BE, AT/ED and non-37-byte assertions. It extracts big-endian unsigned signCount, including zero, but **never makes counter updates or authorization decisions**. No SQL call or HTTP endpoint is exposed; existing direct approver SQL routines can still bypass all unsigned preflights. The privileged verifier under #38 MUST cryptographically validate original `authenticatorData || SHA256(original clientDataJSON)`, check registered credential/UV/identity, implement counter/backup anomaly policy and transactional one-use bound decisions, and revoke direct decision SQL grants. See [ADR 0019](../adr/0019-webauthn-authenticator-data-preflight.md) and [operator guidance](WEBAUTHN_AUTHENTICATOR_DATA.md). No WORM or QTSP claim.
