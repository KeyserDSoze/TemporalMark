# Delivery roadmap — test-driven slices

Progress is recorded in issues and CI, not inferred from this file. Every slice has tests first, then implementation, then security and evidence review.

## 0. Project foundation
- [x] ADR, legal gap register, repository layout and `main` convention.
- [ ] Stable .NET/Node dependency versions and verified CI on GitHub Actions.
- [ ] Local docker compose up: PostgreSQL, OIDC IdP, API, frontend, object store and observability.

## 1. Multi-tenant core
- [ ] Organizations, memberships, invite/accept, last-active-admin invariant, per-tenant roles.
- [ ] Server-side isolation, fail-closed authentication, audit logs, tenant-specific dashboards and period exports.
- [ ] Database migrations + PostgreSQL RLS and cross-tenant integration tests.

## 2. Timestamp MVP
- [ ] RFC 3161 request and response, DER parsing, CMS signature and messageImprint/nonce checks, negative test corpus.
- [ ] Delegated qualified TSA connector, historical EU Trusted List checks and qualified-status evidence.
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
