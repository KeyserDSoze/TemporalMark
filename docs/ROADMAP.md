# Delivery roadmap — test-driven slices

Progress is recorded in issues and CI, not inferred from this file. Every slice has tests first, then implementation, then security and evidence review.

## 0. Project foundation
- [x] ADR, legal gap register, repository layout and `main` convention.
- [ ] Stable .NET/Node dependency versions and verified CI on GitHub Actions.
- [ ] Local docker compose up: PostgreSQL, OIDC IdP, API, frontend, object store and observability.

## 1. Multi-tenant core
- [ ] Organizations, memberships, invite/accept, last-active-admin invariant, per-tenant roles. PostgreSQL atomic bootstrap/commit-time invariant and concurrency integration tests delivered in #22; signed-token OIDC operator CLI and DB role separation are pilot-complete (#24); Keycloak RFC7662 live token-status gate implemented under #26; approval-gated request/approve/complete (#29) and current Keycloak effective-role+enabled directory checks (#30) implemented; signed ACR/auth_time freshness policy (#32) and explicit V008 approval provenance (#33) are implemented but disposable browser OTP/PKCE step-up regression (#34) implemented; production interactive MFA governance and database-backed review SHA confirmation (#36) and terminal scoped rejection (#37), but independently signed human consent (#31/#35), invite/claim sync, management and RLS remain open (#25/#23/#14).
- [ ] Server-side isolation, fail-closed authentication, **legally sealed** audit logs, tenant-specific dashboards and complete period exports. Pilot tenant access audit (#21) covers prepared ZIP/TSR downloads only; independent WORM sealing, issuance audit and RLS remain.
- [ ] Versioned PostgreSQL migrations (V001–V010 implemented, including scoped approvals), **RLS and cross-tenant** integration tests. Dedicated development DB roles and signed-token checks delivered in #24; production secret injection, migration job and production IAM/revocation-TOCTOU controls and formally attested MFA/human approval remain required; Keycloak token introspection implemented in #26 but no Entra adapter.

## 2. Timestamp MVP
- [ ] RFC 3161 request and response, DER parsing, CMS signature and messageImprint/nonce checks, negative test corpus.
- [ ] Basic RFC3161 connector (not yet interoperability-tested against a real TSA); historical EU Trusted List checks and qualified-status evidence.
- [ ] Content-addressed WORM evidence objects, signed manifests and offline verification/exports.
- [ ] No simulated/demo mark may be labelled qualified.

## 3. Own TSA qualification candidate
- [ ] TSU/HSM adapters (on-prem PKCS#11; Azure evaluated HSM), key ceremonies, cert EKU and rotation.
- [ ] Traceable UTC(k) topology, halt-on-desync and testable safety interlocks.
- [ ] SIEM, incident playbooks, BC/DR evidence, immutability and external pen tests.
- [ ] Policy/CPS/PDS, organizational systems, CAB pre-assessment and AgID procedure.

## 4. Production deployments
- [ ] Terraform Azure modules, least privilege and secrets via Managed Identity + Key Vault.
- [ ] On-prem Helm/Compose production reference, source-available dependencies and evidence of WORM/HSM/time integration.
- [ ] Production DR, backup restoration, privacy threat model, support SLAs, maintenance and retention review.

**Definition of Done:** tests green, security review, audit evidence links, repeatable deployment and explicit compliance-state label.
