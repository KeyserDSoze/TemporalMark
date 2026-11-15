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
