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
- [x] #45 TDD-first registration-intent foundation on `main`: ADR 0021, V013 owner-pinned HTTPS issuer/RP policy with forward-only V014 strict DNS integrity, registrar-only NOLOGIN group with no login/members, 48-byte nonce, <=2-minute TTL, one-per-issuer/reviewer/RP append-only storage, privilege/negative/concurrency PostgreSQL tests, no trusted key or signup endpoint. **Does NOT deliver WebAuthn registration or independent registrar proof.**
- [x] #45 exact-head four-job GREEN and closed: https://github.com/KeyserDSoze/TemporalMark/actions/runs/43739456055
- [ ] #44 **true enrollment** with independent real registrar authentication and witness, maintained FIDO2 attestation verification, credential registry+unique IDs, revocation/rotation/recovery and browser tests; NOLOGIN group must not gain a demo/automatic registrar login.
- [ ] #38 **real verified reviewer decision** with trusted enrolled public key, signed assertion/UV, current IAM, atomic challenge consumption and removal of legacy direct SQL decision grants; #35/#31/#27 and independent WORM/QTSP #17/#13 remain OPEN.


### #45 post-RED SQL integrity follow-up

- [x] V014 immutable forward-only RP-name hardening after RED tests for literal IPv4, overlong DNS labels and numeric-only TLD; never rewrite checksummed V013.
- [x] 14 migrations verified with all four CI jobs for #45: https://github.com/KeyserDSoze/TemporalMark/actions/runs/43739456055

## Independent registrar identity preparation (#47; #46/#44 open)

- [x] RED-first xUnit dual RS256-signed registrar/reviewer tokens with distinct OIDC audiences/roles, pinned issuer, 120-second ACR/iat/auth_time policy, fresh RFC7662 live status and independently fetched current effective realm roles for both identities. Unit negative matrix for signature, role/audience, stale/weaker MFA claims, incorrect reviewer/exclusions, revoked/disabled accounts, IdP outage and no cache. ADR 0022 and runbook. **Pure preflight, no CLI/API/SQL, no credential creation.**
- [x] #47 exact HEAD four-job CI GREEN and closed: https://github.com/KeyserDSoze/TemporalMark/actions/runs/43743827253
- [ ] #46 still OPEN: configure and verify real Keycloak browser two-person **registrar** MFA and live current-directory authority, independently approved registrar SQL executor and one-time binding to pinned V013 intent, fail-closed Entra adapter.
- [ ] #44 still OPEN: maintained FIDO2 `create()` attestation, active globally unique trusted credential registry, key revocation/recovery and separate-human approval. #38 still OPEN: reviewer-held signed original decision, atomic one-time challenge consumption and removal of historical direct SQL decision grants. #35/#31/#27 and WORM/QTSP #17/#13 remain OPEN.

## Disposable real registrar Keycloak browser MFA proof (#48)

- [x] RED-first isolated Playwright registrar OTP/PKCE test, distinct test identity/audience, wrong-OTP denial, new-browser strong ACR; explicit actual RS256/JWKS verification, state+S256-PKCE check and 0600 token cleanup. CI-only Keycloak realm gained a separate registrar role and read-only current-directory/introspection clients.
- [x] Real .NET identity gate test added with original Keycloak-signed registrar and reviewer browser MFA tokens, fresh RFC7662 and effective directory roles, followed by role-removal and disabled-account negative checks of the SAME previously valid bearer. Strict HTTPS in production, only one explicit hardcoded disposable HTTP fixture issuer for CI. No privilege/SQL/WORM change.
- [ ] #48 exact-final-HEAD four-job GitHub CI verification and closure only after all GREEN; early RED and subsequent failing CI must be recorded in issue. This is a disposable CI proof, NOT actual WebAuthn registration.
- [ ] #46 real approved production registrar step-up/current-role governance, secure narrowly authorized SQL executor and replay-safe V013 intent binding; #44 maintained FIDO2 `create()` registration attestation/key and revocation, #38 signed reviewer approval/SQL grant cutover. #35/#31/#27, legal #13 and WORM #17 remain OPEN.

## Standalone two-person registrar intent issuance (#49; #46 still open)

- [x] Test-first .NET 10 `ReviewerRegistrationIntentWorkflow` couples BOTH independently signed+strong, live and current-role OIDC registrar/reviewer principals to an immutable approved reviewer subject and server-pinned HTTPS issuer/RP/origin (ADR 0024). **Only** after both checks may an `IReviewerRegistrationIntentStore` request the V013-generated, 48-byte, unconsumable nonce. Bound metadata, short TTL and one-ever uniqueness tested. No WebAuthn attestation, accepted key, browser registration or approved organization decision.
- [x] Npgsql registrar store uses a **dedicated, separately configured restricted SQL LOGIN**, checking actual session_user/current_user, registrar NOLOGIN-group membership, non-superuser/CREATEROLE/CREATEDB status and absence of direct SELECT/DML on intent/policy tables. Existing owner, approver, provisioner/API SQL identities denied. Disposable per-test restricted login is created/removed in CI, **never seeded in migrations**.
- [x] Standalone isolated `registrar-intent` CLI mode requires owner-only two JWT files, real HTTPS pinned issuer, separate audiences and confident ACR, confidential Keycloak introspection/directory, reviewed RP + reviewer stable subject and dedicated SQL connection. **Not a public API/PWA endpoint**. Real production CAB/vault login/key lifecycle is NOT auto-created.
- [ ] #49 exact-head four-job backend/frontend/terraform/docker-smoke CI green and close only with evidence. This is a bounded **non-authorizing** integration slice; a compromised SQL registrar login can call the function directly.
- [ ] #46 independently approved actual production registrar service custody/ACL, append-only verified identity/action audit, replay-safe one-time WebAuthn ceremony consumption, secure rollover/renewal and Keycloak-to-DB TOCTOU controls. #44 maintained FIDO2 registered-credential verification/revocation and #38 signed reviewer decision + legacy SQL grant removal remain OPEN. #35/#31, WORM #17 and legal/QTSP #13 remain OPEN.

- [x] #49 separate SQL-role hardening: RED tests for every conflicting approver/provisioner/runtime group membership (`c5e2501`), GREEN same-connection `pg_has_role` denial (`fe5e38d`), CI-only role grants revoked and account removed. No automatic registrar role seeded.

## V015 security stop-line for registrar SQL issuance (#51)

- [x] **RED before V015:** PostgreSQL tests require the NOLOGIN registrar group to have **no EXECUTE** on the original unsigned V013 nonce function; existing V014 granted it. Security decision in [ADR 0025](../adr/0025-fail-closed-registrar-sql-issuance-interlock.md) was recorded before the test.
- [x] **GREEN:** V015 forward-only REVOKE of V013 registrar, PUBLIC and legacy SQL EXECUTE; fail-closed Npgsql adapter refuses even after accidental direct regrant. Tests adapt previous #49 positive case to negative explicit suspension, while preserving schema-owner one-ever nonce metadata diagnostics and all other role/tenant deny cases.
- [x] CI migration-count and persistent-seed check expect **15** immutable scripts, no change to V001–V014; operator runbook and threat model updated.
- [ ] #51 close **only after** exact-head four-job backend/frontend/terraform/docker-smoke GitHub Actions SUCCESS.
- [ ] #50 **still OPEN**: actual independently enrolled, approved WebAuthn public key, verified signed registrar/reviewer consent bound to original RP/issuer/nonce and atomic one-time SQL release/credential activation, with audit and key revoke/recovery. #46/#44/#38 and WORM/QTSP #17/#13 remain OPEN. The #49 CLI is deliberately suspended; never regrant V013 as a shortcut.

### V016 follows V015, preserving the fail-closed stop-line

- [x] RED SQL privilege-escalation regression `3adb509`: a registrar LOGIN accidentally granted direct function EXECUTE must **still be denied at INSERT** even when the .NET store is bypassed. Earlier V015 only denied the group grant. 
- [x] GREEN `V016__registration_intent_owner_only_insert.sql`: secure-definer trigger rejects nonowner session_user, including directly granted legacy V013 caller; owner untrusted metadata diagnostics remain intact.
- [x] Migration and CI persistent count advanced from 15 to **16**, prior V001–V015 checksums untouched; ADR 0025 and operator runbooks updated.
- [ ] #51 exact FINAL main-head four-job green for **V016** before closing. #50/#46/#44/#38 remain OPEN for actual trusted WebAuthn signer and atomic one-time release.

## Maintained Fido2 WebAuthn registration candidate adapter (#52)

- [x] Reviewed stable Fido2 **4.3.3** MIT/.NET10 and actual version-tagged four-method `IFido2` API; pinned in infrastructure project; ADR 0026 before RED tests.
- [x] RED-first tests for immutable 48-byte stored challenge and 32-byte reviewer handle, pinned RP/HTTPS scope, independent registrar/reviewer identity, 2-minute lifetime, required UV and direct attestation, raw malformed/oversized attestation, self/none rejection and mismatched credential outputs. GREEN isolated `ReviewerRegistrationAttestationCandidateVerifier` invokes Fido2 `MakeNewCredentialAsync` and returns only **UNAPPROVED** digest/format metadata. Real stable library must reject bogus clientDataJSON/CBOR; fake-positive test ONLY exercises quarantined result, not hardware.
- [ ] #52 exact-final-head GitHub backend/frontend/terraform/docker-smoke all SUCCESS before closing child.
- [ ] #44/#50 still OPEN: real independent registrar and trusted reviewer authorizations, genuine browser/device positive attestation, approved metadata/CA trust and verified globally unique COSE key registry with atomic credential registration and revocation/recovery. #38 remains OPEN for signed decision and old direct SQL reviewer-grant removal. V015/V016 **remain frozen**, no user-visible registration API. WORM/AgID/QTSP #17/#13 gates untouched.


## Real-library packed attestation regression (#54; parent #53 open)

- [x] ADR 0027 before RED: real Fido2 4.3.3 x5c/ES256 packed attestation test scope, intentionally untrusted test-only PKI and signed-MDS trust obligations.
- [x] Test-first RED commit `7c80ede` ([expected CI failure](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43770129697)); ephemeral signed fixture, real-library positive hashed-only `UNAPPROVED`, and mutation negatives added. `System.Formats.Cbor` pinned to patched 10.0.15 after CI detected CVE-2026-118747 in version 10.0.0.
- [ ] #54 close only after **exact final-head** backend/frontend/terraform/docker-smoke CI success; no fake-positive success claim.
- [ ] #53 production trust: signed FIDO MDS BLOB/chain and root governance, AAGUID model policy/status revocation, certificate renewal, integration with actual virtual/physical authenticator and tested fail-closed outage, privacy impact and CAB review. Actual reviewer-signed and SQL-atomic authorization remains #44/#50/#46/#38. No deployment of test CA/keys, ACTIVE enrollment, approval permissions, WORM or QTSP status.
