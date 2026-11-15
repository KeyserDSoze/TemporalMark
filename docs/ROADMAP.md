# Delivery roadmap — test-driven slices

Progress is recorded in issues and CI, not inferred from this file. Every slice has tests first, then implementation, then security and evidence review.

## 0. Project foundation
- [x] ADR, legal gap register, repository layout and `main` convention.
- [ ] Stable .NET/Node dependency versions and verified CI on GitHub Actions.
- [ ] Local docker compose up: PostgreSQL, OIDC IdP, API, frontend, object store and observability.

## 1. Multi-tenant core
- [ ] Organizations, memberships, invite/accept, last-active-admin invariant, per-tenant roles. PostgreSQL atomic bootstrap/commit-time invariant and concurrency integration tests delivered in #22; signed-token OIDC operator CLI and DB role separation are pilot-complete (#24); Keycloak RFC7662 live token-status gate implemented under #26; approval-gated request/approve/complete (#29) and current Keycloak effective-role+enabled directory checks (#30) implemented; signed ACR/auth_time freshness policy (#32) and explicit V008 approval provenance (#33) are implemented but disposable browser OTP/PKCE step-up regression (#34) implemented; production interactive MFA governance and database-backed review SHA confirmation (#36) and terminal scoped rejection (#37), but unsigned server challenge (#39), but independently signed human consent (#31/#35), invite/claim sync, management and RLS remain open (#25/#23/#14).
- [ ] Server-side isolation, fail-closed authentication, **legally sealed** audit logs, tenant-specific dashboards and complete period exports. Pilot tenant access audit (#21) covers prepared ZIP/TSR downloads only; independent WORM sealing, issuance audit and RLS remain.
- [ ] Versioned PostgreSQL migrations (V001–V012 implemented, including scoped approvals), **RLS and cross-tenant** integration tests. Dedicated development DB roles and signed-token checks delivered in #24; production secret injection, migration job and production IAM/revocation-TOCTOU controls and formally attested MFA/human approval remain required; Keycloak token introspection implemented in #26 but no Entra adapter.

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

## Identity next increment (#40)

- [x] Strict, test-first .NET 10 validation-only `ReviewerWebAuthnRelyingPartyPolicy` (explicit canonical HTTPS origin + exact RP host, no caller-selected authority) with ADR 0017, threat model and on-prem/Azure checklist. **This does not verify any WebAuthn assertion and adds no endpoint.**
- [x] #40 CI four-job GREEN, closed: https://github.com/KeyserDSoze/TemporalMark/actions/runs/43733494605
- [ ] Independently approved WebAuthn key enrollment, actual signed reviewer action, secure RP/origin/UV/signCount verification, one-time atomic signed decision, revocation of legacy direct SQL grants and independent identity-governance review under #38. Parents #35/#31/#27 and qualified-evidence #17/#13 remain OPEN.

## WebAuthn signed assertion preparation (#41)

- [x] RED-first .NET clientDataJSON preflight tests and implementation on main: original 48-byte V012 challenge canonical base64url, exact server-pinned HTTPS origin, `webauthn.get`, top-level-only cross-origin denial, strict bounded UTF-8/JSON and duplicate protection; unknown fields/order tolerated. ADR 0018 and operator guidance. **Not a signed assertion, API, or authorization.**
- [x] #40 and #41 exact-head four-job CI verified and closed: https://github.com/KeyserDSoze/TemporalMark/actions/runs/43733494605 and https://github.com/KeyserDSoze/TemporalMark/actions/runs/43734321937
- [ ] #38 real independently approved WebAuthn key enrollment and maintained signature verifier with UV/RP hash, registered key/counter/replay checks; atomic approval/rejection plus old direct SQL grant removal and human decision UX. #35/#31 and WORM/QTSP #17/#13 remain OPEN.

## WebAuthn signed-data structural foundation (#42)

- [x] RED-first .NET 10 basic `authenticatorData` 37-byte-only preflight: SHA-256 of approved RP ID compared constant-time, mandatory UP/UV, no RFU1/RFU2/AT/ED, legal BE/BS combinations, unsigned big-endian `signCount` parsing only (zero allowed). ADR 0019 and security/runbook docs. **All bytes are untrusted without verified credential signature; no new API, SQL grants, enrollment or decision.**
- [x] #40/#41/#42 four-job exact-head CI verified and issues closed; see latest dated audit entries below.
- [ ] #38: independently registered and approved key, signed WebAuthn assertion with maintained library, original bytes binding, human explicit review, counter policy, atomic challenge consumption, SQL grant cutover and independent assurance. Keep #35/#31 and WORM/QTSP #17/#13 open.

## WebAuthn exact signature bytes — next increment (#43)

- [x] #40, #41 and #42 **CLOSED** with four-job exact-head green CI respectively: [CI #103](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43733494605), [CI #112](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43734321937), [CI #121](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43735515968). These are structurally constrained **untrusted** policy helpers, not real WebAuthn signature verification.
- [x] #43 RED-first source contract and pure raw byte-exact transcript helper on `main` (ADR 0020). No runtime integration, signing authority, new SQL grant, registration/assertion API or approval action. The original client JSON must not be normalized or reserialized.
- [x] #43 exact-head four-job CI verified GREEN and closed: https://github.com/KeyserDSoze/TemporalMark/actions/runs/43737165746
- [ ] #38 independently governed credential registration, maintained WebAuthn/FIDO2 signature verifier against *registered* key, UV/RP/nonce/action/scope/counter and current role, explicit human consent UI, atomic signed decision and removal of existing direct SQL bypass. #35/#31/#27 and legal/WORM #13/#17 stay OPEN.

## Reviewer-held WebAuthn registration governance (#44/#45)

- [x] #43 **closed** after exact-head four-job green [CI 43737165746](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43737165746), SHA `ee923d0` (byte-exact **untrusted** signing message, no verifier).
- [x] #45 TDD-first registration-intent foundation on `main`: ADR 0021, V013 owner-pinned HTTPS issuer/RP policy, registrar-only NOLOGIN group with no login/members, 48-byte nonce, <=2-minute TTL, one-per-issuer/reviewer/RP append-only storage, privilege/negative/concurrency PostgreSQL tests, no trusted key or signup endpoint. **Does NOT deliver WebAuthn registration or independent registrar proof.**
- [ ] #45 exact-head backend/frontend/terraform/docker-smoke CI success and closure after verified run; initial RED and subsequent migration runs to be linked in issue.
- [ ] #44 **true enrollment** with independent real registrar authentication and witness, maintained FIDO2 attestation verification, credential registry+unique IDs, revocation/rotation/recovery and browser tests; NOLOGIN group must not gain a demo/automatic registrar login.
- [ ] #38 **real verified reviewer decision** with trusted enrolled public key, signed assertion/UV, current IAM, atomic challenge consumption and removal of legacy direct SQL decision grants; #35/#31/#27 and independent WORM/QTSP #17/#13 remain OPEN.
