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
