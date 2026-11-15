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
