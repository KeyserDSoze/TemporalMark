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


## Metadata model inspection and signed-MDS root blocker (#56 / #55)

- [x] ADR 0028 before RED tests; conservative non-authorizing metadata policy inspection using actual pinned Fido2 4.3.3 **model classes**, NOT a verified MDS JWT or production hardware attestation. Focused child #56; [operator runbook](WEBAUTHN_MDS_POLICY.md).
- [x] RED tests require refusal for revoked/security-bypassed/compromised/unknown status, missing duplicate/mismatched AAGUID, malformed/no attestation roots, unsupported protocol or attestation, serial rollback, stale/future observation, and non-`UNAPPROVED` result; GREEN pure `.NET 10` policy returns `UNAPPROVED` only.
- [ ] #56 close only after **exact final-head** four-job GitHub CI GREEN; the metadata objects in tests are **unsigned**, so no trust claim.
- [ ] #55 next work: true signed/JWS x5c and CRL/revocation validation, GlobalSign **R46** root transition with R3 cross-cert (August 2026, R3 and cross-cert expire **2029-03-18**), separate signed/persisted monotonic metadata checkpoint, AAGUID-specific attestation CA and trust policy, air-gap/DR/SSRF constraints and DPIA. Fido2 **4.3.3** upstream R3-pinned MDS repository requires independent root/CRL audit before production. Never re-enable V015/V016, credential trust or SQL approval merely from policy inspection. Parent #53 and #44/#50/#46/#38 remain OPEN.


## Real signed FIDO MDS JWS/X509 cryptographic preflight (#58; #57 still blocked)

- [x] ADR 0029 reviewed and committed before RED, addressing FIDO 2026 GlobalSign R3→R46 migration, pinned Fido2 4.3.3 revocation split, and explicit no-production-trust boundaries.
- [x] RED xUnit uses disposable separate RSA test CA/leaf and **real** RS256 signed `x5c` compact JWS; verifies rejection of tampered JWS/signed claims, wrong/unpinned root, extra injected cert, malformed/duplicate/untrusted header, stale/future `iat`, expired/not-yet-valid signing cert, invalid serial and oversized input. GREEN code uses maintained Microsoft.IdentityModel JWS verifier and `X509ChainTrustMode.CustomRootTrust`, not a fake-JWT positive or host CA fallback. No API/DB/CLI caller.
- [ ] #58 close **only** after final-head four-job CI green; follow [JWS precheck runbook](WEBAUTHN_MDS_JWS_PRECHECK.md). All outputs stay `UNAPPROVED`: chain construction uses `X509RevocationMode.NoCheck` **only as test-only cryptographic proof**, NEVER production certificate trust.
- [ ] #57 mandatory production security: R46 root governance, actual 2026 cross-cert chain compatibility, full CRL/OCSP revocation **for every path** across on-prem/Azure, signed metadata serial/digest anti-rollback, refresh/airgap/outage safety, CAB and DPIA. #55/#53/#44/#50/#46/#38 remain OPEN; V015/V016 and registrar CLI are suspended. No qualified timestamp/WORM status implied.


## Offline issuer-signed CRL cryptography (#59; full #57 remains OPEN)

- [x] ADR 0030 before TDD RED: a **non-authorizing** direct issuer/leaf X.509 v2 DER CRL regression. Official FIDO MDS changed R3→R46 in August 2026; pre-existing Fido2 4.3.3 JWS uses R3 + divergent revocation branches; this increment **does not** trust either.
- [x] RED-first xUnit with ephemeral real RSA CA and leaf, real BouncyCastle 2.7.0-signed DER CRLs; rejects revoked serial, invalid CRL signature, wrong issuer, future/expired/missing nextUpdate, missing cRLSign, unsupported critical/delta/indirect CRL, invalid DER and expired certificates.
- [x] GREEN isolated `ReviewerMdsOfflineCrlCandidateVerifier`: real BC parser/signature/serial check + explicit one-hop certificate chain. Always `UNAPPROVED`, label `CRL_SIGNATURE_CHECK_ONLY_ROOT_UNTRUSTED`, never public key, ACTIVE credential or tenant authorization. No CRL fetching, Azure dependency or SQL privilege change. [Runbook](WEBAUTHN_MDS_OFFLINE_CRL.md).
- [ ] #59 close only after all four exact-final-main CI jobs GREEN and security review of test/implementation output.
- [ ] #57 / #55 production work: independent FIDO R46 root (R3 cross-cert until 2029-03-18), full JWS x5c chain CRL/OCSP **every intermediate**, CRL issuer CDP/AKI/number/anti-rollback, managed signed network/offline import, outage and SSRF tests, persistent signed MDS state, model-specific attestation chain, CAB/privacy. Keep #53/#44/#50/#46/#38 OPEN, registrar CLI and V015/V016 frozen; no eIDAS/QTSP/WORM claims.


## Two-hop independently issuer-signed CRL regression (#60; parent #57 still OPEN)

- [x] ADR 0031 committed before RED tests on `main`. X.509 PKI fixture generates ephemeral three-tier root → intermediate CA → signer leaf and **two real issuer-signed DER CRLs** at test runtime.
- [x] RED-first tests cover intermediate revocation as well as leaf revocation, swapped/missing/forged CRLs, foreign CA/root, CA `cRLSign`, expired/future CRLs, unsupported delta/indirect CRLs and path cardinality.
- [x] GREEN pure offline .NET 10 `ReviewerMdsOfflineTwoHopCrlCandidateVerifier`: exact `CustomRootTrust` path with downloads blocked, and **both non-root certificates** checked by the *same* BouncyCastle 2.7.0 CRL signature/issuer/date/revocation helper already used by #59. No host trust, CRL URL, SQL/CLI/API integration or production root. Every observation is **`UNAPPROVED`**. [Runbook](WEBAUTHN_MDS_TWO_HOP_CRL.md).
- [ ] Close #60 only after the exact final `main` HEAD passes four CI jobs (backend/frontend/terraform/docker-smoke).
- [ ] Production #57/#55: independent real FIDO root R46 custody, signed MDS JWT 2026 R3/R46 cross-cert path, actual all-hop CRL/OCSP and issuer AKI/CDP, signed CRL imports including air-gap, persistent monotonic CRLNumber+signed MDS snapshot, outage/time/SSRF and CAB/DPIA. This is an **untrusted test root**, not true manufacturer revocation provenance. V015/V016 and WebAuthn/SQL enrollment remain frozen; #53/#44/#50/#46/#38 OPEN. No eIDAS/WORM claims.


## SQL-only owner-staged MDS/CRL candidate checkpoint (#62; parent #61 OPEN)

- [x] ADR 0032 before RED tests documents PostgreSQL 17 per-key transactional lock, owner-only untrusted evidence source and **no credential-authorization integration**.
- [x] RED live PostgreSQL regression: first/equal/higher candidate serial, digest equivocation at equal serial, rollback, changed policy, bad issuer/hash/TTL, expired/clock-backwards checkpoint, append-only pilot history, role privilege denial, concurrent independent SQL sessions with conflicting versions.
- [x] GREEN V017 migration and CI count=17 (V001–V016 unchanged): only physical DB table-owner SQL session can stage **UNAPPROVED** candidate serial+SHA256; no PUBLIC/approver/provisioner/runtime/registrar access. No real MDS JWT/CRL/trust root verified by SQL. [Runbook](MDS_CRL_UNAPPROVED_CHECKPOINT.md).
- [ ] #62 closes only after exact-final-main **four job** CI GREEN; parent #61 remains OPEN for a real independently verified signed input and externally witnessed monotonic checkpoint, multi-primary/backup restore corruption and clock rollback tests, immutable audit, authentically distributed CRLNumber/issuer AKI+CDP, real FIDO R46 roots/cross-chain governance, CAB/DPIA and fail-closed offline/Azure parity.
- [ ] #57/#55/#53/#44/#50/#46/#38 remain OPEN; V015/V016 SQL stop-line and suspended registrar CLI untouched, no WebAuthn enrollment, WORM/eIDAS/QTSP claim.

## Offline signed witness vs V017 candidate snapshot — cryptographic test (#63)

- [x] ADR 0033 before RED xUnit tests, after review of ADR 0025–0032 and V017. Witness is **detached RSA-PSS SHA256**, original bytes domain-separated and fully canonical, signed by **ephemeral untrusted test key**.
- [x] RED live PostgreSQL tests for `UNAPPROVED` positive scoped matching and negative forged/wrong key, tampered, duplicate/reordered/noncanonical/oversized/expired witness, missing/extra/current-higher/restored-lower/equivocated database row, expired SQL checkpoint and unprivileged role.
- [x] GREEN `ReviewerMdsOfflineSignedCheckpointWitnessReconciler`: only reads an exact source-policy partition inside `REPEATABLE READ READ ONLY`, matches every signed kind+issuer+version+digest against V017, physical table owner login only, no network, new SQL grants, schema migration, CLI or registration. **All observations UNAPPROVED**. [Runbook](MDS_CRL_SIGNED_WITNESS_RECONCILIATION.md).
- [ ] Close #63 only after exact-main four-job CI GREEN and RED proof; keep #61 OPEN. A caller-chosen verification key and a signed manifest do not establish externally protected **latest** version or detect an old witness replayed with an old DB backup. Full restore/cross-region/clock and root custody audit still required.
- [ ] #61/#57/#55/#53/#44/#50/#46/#38 still BLOCKING real FIDO R46 trusted root, signed MDS/issuer CRLs, witnessed immutable version, live attestation and independent WebAuthn enrollment. V015/V016/sql registrar CLI remain frozen; no WORM/QTSP/eIDAS claim.

## Test-only high-water seal and scoped COPY rollback regression (#65; #64 remains OPEN)

- [x] ADR 0034 first, after ADR 0032–0033 and existing V017 docs review; no migration change, production root, active reviewer or registrar SQL grant.
- [x] RED xUnit uses two ephemeral RSA-PSS signers, domain-separated original-byte manifest/seal, explicit pinned *test* authority SPKI SHA256 and latest seal SHA256. Real live PostgreSQL 17 `COPY (SELECT ... WHERE policy) TO STDOUT` and `COPY ... FROM STDIN` export/restore an old candidate while the latest seal digest is held **outside the database in test process memory**.
- [x] GREEN offline `ReviewerMdsOfflineSealedHighWaterCandidateVerifier` verifies signed high-water seal, exact policy+manifest digest binding, canonical UTC window and two caller-supplied test pins, then delegates to existing ADR 0033 read-only full partition comparison. No new trust roots/production keys, network, API/CLI, SQL writes or migration. All outputs **UNAPPROVED**. [Runbook](MDS_CRL_SEALED_HIGH_WATER_COPY_RESTORE.md).
- [ ] Close scoped #65 only once final `main` HEAD has all four GitHub Actions jobs green (backend/frontend/terraform/docker-smoke), including live PostgreSQL copy restore tests.
- [ ] #64 remains OPEN for true independent immutable latest-seal key/digest custody, full `pg_dump/pg_restore`/PITR, high-water replay after old backup+old seal, replica/split-brain clock and failure paths, on-prem OSS/Azure equivalence and CAB. #61/#57/#55/#53/#44/#50/#46/#38 stay OPEN, FIDO R46 signed provenance and actual revocation unresolved. V015/V016 interlock frozen; no WORM/QTSP/eIDAS status.

## Complete logical PostgreSQL dump/restore synthetic high-water seal test (#66)

- [x] ADR 0035 before RED xUnit and mandatory Docker CI integration step, after review of V017, ADR 0032–0034 and official PostgreSQL 17 `pg_dump/pg_restore` guidance.
- [x] RED xUnit `MdsFullPgDumpRestorePostgresTests` initially references the missing fixture, and Docker CI requires the as-yet missing integration runner before GREEN; then add test-only disposable RSA-PSS manifest/seal fixture and `tests/integration/mds-full-pgdump-restore.sh`.
- [x] Real `pg_dump --format=custom` of the **full logical test database**, then `pg_restore --single-transaction --no-owner --exit-on-error` into a separate disposable PostgreSQL database on the same test server. **Retain ACL** and assert SQL V017 function/table access restrictions; avoid unsafe `--no-acl`. Schema migrations remain **17**. xUnit reconciles old restored serial 3 vs latest live serial 4 with two disposable RSA-PSS signatures and retained latest test-seal digest; output **UNAPPROVED**. [Runbook](MDS_CRL_FULL_PGDUMP_RESTORE_TEST.md).
- [ ] Close #66 only after **final main HEAD** GitHub Actions backend/frontend/terraform/docker-smoke all SUCCESS, including full logical restore and actual Keycloak MFA.
- [ ] Parent #64/#61 remain OPEN: a single server's logical restore is not full-cluster/PITR/availability or cross-region DR; latest seal pin is still in CI memory, not externally protected monotonic authority. Real immutable off-DB witness custody, root and key rotation, real FIDO R46 trust and CRL provenance, human/CAB governance and operational recovery remain blocked (#57/#55/#53/#44/#50/#46/#38). SQL V015/V016 and registrar CLI freeze unchanged; no WORM/eIDAS/QTSP claim.

## File-backed signed high-water checkpoint prototype (#67, #64 remains OPEN)

- [x] ADR 0036 before RED tests, after reviewing ADR 0032–0035, V017, full logical pg_dump/pg_restore runbook and .NET 10 file-stream flush/exclusive-open semantics.
- [x] RED xUnit `ReviewerMdsOfflineFileHighWaterJournalTests` covering mandatory preexisting journal, original-byte RSA-PSS signatures and pinned **test** SPKI, strict monotonic serial, hash-linked previous payload, corrupt/truncated/replaced file, stale/future clock and concurrent writers.
- [x] GREEN `ReviewerMdsOfflineFileHighWaterJournal` is a separate **normal file** outside PostgreSQL: `CreateNew` explicit *test-only bootstrap*, read/append must open existing valid file exclusively, verify all signatures and chain, bounded inputs, append+Flush(true). Only `UNAPPROVED` observations; no production root or registrar rights. [Runbook](MDS_CRL_SIGNED_FILE_HIGH_WATER_JOURNAL.md).
- [x] Extend existing mandatory full logical PostgreSQL `pg_dump/pg_restore` CI regression: append signed serial 3→4 journal entries on disk, re-open **after** restoring old database, reconcile old signed witness+seal against latest *file-derived* digest, and demonstrate whole-file restore still rolls back to signed older journal version.
- [ ] Close scoped #67 only after RED confirmed and all **four final main HEAD** GitHub Actions jobs green (backend, frontend, terraform, docker-smoke).
- [ ] Parent #64 and #61 remain RELEASE BLOCKING: actual separate independently governed immutable offsite monotonic authority, CAB-approved signer key bootstrap/rotation, ACL/host/symlink and partial-write protection, external latest high-water anchor, full-cluster PITR, cross-region/OS compromise and on-prem/Azure DR. Genuine FIDO R46/JWS/CRL source and reviewer-held credential remain #57/#55/#53/#44/#50/#46/#38. V015/V016 SQL freeze unchanged; no WORM/eIDAS/QTSP trust claim.

## Visible symlink/reparse hardening for offline signed test journal (#68)

- [x] ADR 0037 recorded before RED tests (reviewed ADR 0032–0036, issue #64 and .NET 10 `FileSystemInfo.LinkTarget`/`ReparsePoint` semantics).
- [x] RED GitHub Actions test creates real signed target journal, symlink to file, symlinked ancestor directory and dangling symlink; verifies inspection/append/bootstrap fail closed and genuine target bytes stay unchanged.
- [x] GREEN .NET test-only `ReviewerMdsOfflineFileHighWaterJournal` validates canonical full path and all existing parent/leaf components before/after file open, rejecting visible symbolic links/reparse points. No changes to SQL, API, CLI or FIDO trust.
- [ ] Close #68 only after four final `main` SHA backend/frontend/terraform/docker-smoke GitHub CI jobs SUCCESS. Parent #64/#61/#57/#55/#53/#44/#50/#46/#38 remain OPEN: checked link attributes are inherently TOCTOU-prone, not O_NOFOLLOW, independent signer key, immutable offsite witness, distributed lock, physical PITR/DR or trusted FIDO R46/JWS/CRL evidence. No WebAuthn activation, WORM/eIDAS/QTSP claim; V015/V016 freeze intact.

## Separate PostgreSQL 17 CI witness server, readonly operator and full restore (#69)

- [x] ADR 0038 before RED, reviewing ADR 0032–0037, immutable V017, Docker CI and PostgreSQL 17 atomic UPSERT/role guidance.
- [x] RED .NET 10 missing separate-reader type in backend tests and real PostgreSQL test contract for DISTINCT `pg_control_system().system_identifier` witness server, owner-only monotonic writer, role/ACL denial and source-policy scoped signed-seal reconciliation. [Test runbook](MDS_CRL_SEPARATE_POSTGRES_WITNESS_TEST.md).
- [x] GREEN disposable Compose **`witness-ci` profile** with separate PostgreSQL 17.6 container, named volume and test passwords, owner-only atomic serial UPERT/audit and read-only reader role. `ReviewerMdsIsolatedPostgresWitnessReader` reads the other cluster's latest seal SHA under `REPEATABLE READ READ ONLY`, verifies narrow reader permissions, delegates cryptography to ADR 0033/0034, returns only `UNAPPROVED`. A restored **full main logical DB** at serial 3 is denied against witness instance retained at 4.
- [ ] Close scoped #69 **only** when exact final `main` SHA CI jobs backend/frontend/terraform/docker-smoke all SUCCESS; keep full integration smoke test mandatory.
- [ ] Parent #64/#61 stay RELEASE BLOCKING: CI witness is neither independently controlled nor immutable, both DB servers owned by same Docker host, no externally approved signing root, CAB/HSM custody, true WORM/offsite monotonic guarantee, physical PITR/region failover, cross-server transaction atomicity or operational on-prem/Azure production parity. #57/#55/#53/#44/#50/#46/#38 and V015/V016 freeze stay open; no eIDAS/QTSP/active WebAuthn claim.

## Isolated CI PostgreSQL witness EXECUTE-only writer privilege separation (#70)

- [x] ADR 0039 documented before RED, after ADR 0032–0038 and PostgreSQL 17 SECURITY DEFINER/PUBLIC grants review. Separate `witness-ci` second PostgreSQL 17 instance remains CI-only, no main V018/SQL grant, no Azure/on-prem production dependency.
- [x] RED **real** xUnit integration attempts to connect as a previously absent non-superuser `temporalmark_witness_writer`, stage strictly increasing synthetic seal serial 3→4 through one limited function and DENY direct table/audit/sequence SELECT/WRITE/TRUNCATE, TEMP/CREATE or `SET ROLE`, with function-owner identity checks. [Runbook](MDS_CRL_EXECUTE_ONLY_WITNESS_WRITER_TEST.md).
- [x] GREEN add NOLOGIN/NOSUPERUSER data owner, non-superuser writer with **only EXECUTE**, restricted SECURITY DEFINER function with pinned catalog search_path and fully qualified `public.` tables, atomic monotonic UPSERT+same-tx append audit, revoke PUBLIC default function/DB TEMP grants in a single bootstrap transaction. Keep SELECT-only reader identity verification.
- [ ] Close #70 only after all four jobs SUCCESS on exact final `main` SHA, including real full logical main DB `pg_dump/pg_restore`, witness second-cluster check, Keycloak MFA and V017 role protections.
- [ ] #64/#61 remain OPEN: witness superuser+CI host still own BOTH volumes and disposable roots, can restore arbitrary valid old snapshots, rewrite events, modify definer or raise synthetic versions. No independently owned append-only/WORM high-water store, CAB/HSM signer key bootstrap/rotation, production OSS on-prem/Azure equivalent, region/PITR or official FIDO R46/JWS/CRL/OCSP trust. #57/#55/#53/#44/#50/#46/#38/V015/V016 registrar freeze remain blocked; no eIDAS/QTSP/ACTIVE WebAuthn claim.

### CI test selection audit correction (#69 reopened)

The previous [#69](https://github.com/KeyserDSoze/TemporalMark/issues/69) four-job GREEN run started a second PostgreSQL cluster but **did not run** `MdsSeparatePostgresWitnessRestoreTests`: the `dotnet test --filter` selected only `MdsFullPgDumpRestorePostgresTests`. #69 was reopened and that claim corrected in its issue comments. The CI test filter now **selects both suites** in the same mandatory restore step. Real RED [43832267622](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43832267622) proved 2 actually selected (1 passed, 1 failed with missing restricted witness-writer login) before SQL GREEN. Both classes are xUnit-serialized in one collection and the old restored snapshot test resets its disposable mutation for the other class. Only re-close #69 and close #70 with **actual two-suite test results** and all 4 final `main` CI SUCCESS, without weakening #64.

## PWA navigation boundary hardening (#71, child #20)

- Production Workbox `navigateFallback` must never substitute cached `index.html` for `/api/`, `/healthz` or `/realms` navigations. Use an anchored `navigateFallbackDenylist`, retain empty `runtimeCaching` and enforce API authentication server-side. The actual Chromium production-worker 200-for-404 RED regression was reproduced on [CI 43842598997](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43842598997). See [ADR 0040](../adr/0040-pwa-navigation-fallback-api-denylist.md), [runbook](PWA_SERVICE_WORKER_SECURITY.md) and [#71](https://github.com/KeyserDSoze/TemporalMark/issues/71) for final GREEN evidence. Broader CI reproducibility, lockfiles, mobile install, SAST/SBOM and cross-tenant tests remain #20.

## Three synthetic high-water observations against coordinated SQL rollback (#72, child #64)

- [x] ADR 0041 test-only decision first (`07db7d9`); RED real full-restore PostgreSQL suite (`96ff10c`, [Actions 43846376009](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43846376009)) compiled against a *missing* three-source verifier and failed with expected `CS0103/CS0246`.
- [ ] GREEN exact-final-main four-job CI for isolated `ReviewerMdsThreeSourceHighWaterCandidateReconciler`, which requires both separate witness PostgreSQL and the signed file journal to match the signed original primary V017 manifest/seal under the same synthetic policy and latest serial/hash. [Runbook](MDS_CRL_THREE_SOURCE_ROLLBACK_TEST.md).
- [ ] Explicit residual: when the same privileged Docker/backup operator replays **both** SQL databases and older correctly signed journal, all three agree on old serial and the result is still only `UNAPPROVED`. Parent #64/#61/#57/#55/#53/#44/#50/#46/#38 remain OPEN. No actual independent HSM/CAB-signed immutable high-water custody or production equivalence on-prem/Azure, no FIDO R46 trust, no activation or eIDAS/QTSP/WORM claim. V015/V016 registrar freeze remains.

## Restricted internal witness audit-history consistency (#73, child #64)

- [x] ADR 0042 before RED (`2fab1ca`); real full-logical PostgreSQL restore RED (`dc90cad`, [CI 43849622989](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43849622989)) proved the preexisting two-source reader wrongly accepted checkpoint version4 when newest audit event4 had a forged SHA (1 of 2 tests failed as expected).
- [ ] GREEN exact-final-head four-job CI for bounded STABLE SECURITY DEFINER, reader-only EXECUTE and `ReviewerMdsIsolatedPostgresWitnessReader` audit/history check in the same read-only repeatable-read witness snapshot. Test owner audit tampering, missing event, serial order, >128 events and unchanged writer/reader SQL grants. [Runbook](MDS_CRL_WITNESS_AUDIT_RECONCILIATION.md).
- [ ] **Still release-blocking:** a witness superuser may rewind both checkpoint and event tail; combined old primary DB + old normal signed file remains undetectable and yields only UNAPPROVED. No offsite/WORM independent monotonic custody, approved CAB/HSM signer/bootstrap, official FIDO R46 root/CRL trust, production OSS on-prem/Azure parity or physical PITR/region proof. #64/#61/#57/#55/#53/#44/#50/#46/#38 stay OPEN, V015/V016 registrar issuance suspended.

## Immutable GitHub Actions references — child #74 of #20

- [x] ADR 0043 committed before RED. Real [CI 43857785628](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43857785628) proved 3 Python unit tests GREEN while the real policy rejected all 10 floating action refs; the local-path traversal regression was caught and corrected first.
- [x] GREEN verified on [CI 43858384707](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43858384707) at 0872290; candidate 354ea83 pins all ten uses declarations to the five verified 40-character upstream action commit SHAs. Keep the policy check in the backend job, preserve all four jobs and verify all on **exact final main SHA** before closing only child #74. [Runbook](CI_ACTION_PINNING.md).
- [ ] Parent #20 remains OPEN: npm lockfiles + npm ci addressed under child #75, pinned container digests and runner/toolchain provenance, SAST/SBOM, attested releases, PWA maskable/install coverage and cross-tenant tests. #64/#61/#57 and V015/V016 security freeze remain unaffected.

## npm v10 dependency lockfiles and clean CI/Docker installs (#75, child #20)

- [x] ADR 0044 before RED. Actual [CI 43861421062](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43861421062): 5/5 Python tests PASS but source policy DENIED both missing lockfiles, unfrozen npm install and Docker clean install mismatch. Initial synthetic fixture shallow-copy bug was corrected in forward commit 5be400c.
- [x] GREEN candidate 842f477: genuine npm v10 v3 registry lockfiles (475 entries PWA, 9 entries tests), all registry packages verified for exact version, HTTPS source, integrity, all CI/npm installs switched to npm ci, Docker COPYs package-lock before clean install and temporary lockfile seed removed. [Runbook](NPM_LOCKED_INSTALLS.md).
- [x] Child #75 closed: verified exact final HEAD 19cf39d on [four-job CI 43862523780](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43862523780), including npm clean-install checks, 64/64 PostgreSQL, 2/2 full backup-restore witness and Keycloak MFA/PWA.
- [ ] Parent #20 remains open for container digests, runners/toolchain provenance, SBOM/SAST, signed release artifacts, mobile install and tenant-isolation coverage. FIDO/witness #64/#61/#57 and V015/V016 freeze unaffected.

## Registry-verified Docker image digest pins (#76, child of #20)

- [x] ADR 0045 before TDD. Real [RED CI 43868733873](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43868733873): 5/5 offline policy unit tests PASS, repository guard explicitly rejected all **eight** floating Docker image occurrences (four FROM and four Compose).
- [x] Public registry manifest SHA256 resolution: initial seed failed without producing any digest; diagnostic [CI 43869063858](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43869063858) returned all six expected manifests from Docker Hub, Quay and MCR. Code commit 16a962a pins eight occurrences and removes the temporary seed. See [runbook](CI_DOCKER_IMAGE_DIGESTS.md).
- [x] Child #76 CLOSED after exact final main c7e193d [four-job SUCCESS CI 43870257729](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43870257729): 5/5 digest policy, PostgreSQL 64/64 and full witness restore 2/2, Keycloak MFA, PWA and Terraform.
- [ ] Parent #20 stays OPEN for runner/build toolchain provenance, signature verification, SAST/SBOM/SCA, signed artifact attestations, PWA mobile install and cross-tenant testing. #64/#61/#57 and V015/V016 registrar freeze remain OPEN.

## Lockfile-derived npm CycloneDX inventories for CI (#77, child of #20)

- [x] ADR 0046 before TDD. Behavioral [RED CI 43873432766](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43873432766): 5/5 new policy unit tests PASS, mandatory source policy FAIL for missing SBOM generation, verification and limited upload.
- [x] GREEN implements deterministic Python-stdlib CycloneDX JSON v1.5 inventories with exact lockfile hash/SRI, path-unique nested packages and scoped npm purls; 474 PWA and 8 Playwright dependencies. [CI 43874005747](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43874005747) generated, verified and uploaded a real seven-day artifact. Backend semantic tamper regressions (7 cases) are mandatory; [runbook](CI_NPM_CYCLONEDX_SBOM.md).
- [x] #77 closed after exact final main `6a48849` [four-job CI 43874834080](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43874834080), including 64/64 PostgreSQL, two full-restore witness tests, PWA/Keycloak and the uploaded 7-day npm SBOM artifact.
- [ ] #20 remains OPEN: .NET/NuGet and OCI/system-wide SBOM, actual security scanning/SCA/SAST, publisher signatures, runner attestation, signed release provenance, long-term evidence retention, mobile PWA installation and authenticated cross-tenant tests. No #64/#61/#57/#17 or V015/V016 release-blocker changes.

## CI restored NuGet CycloneDX inventory for all nine .NET projects (#78, child of #20)

- [x] ADR 0047 before RED; [CI 43877379110](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43877379110): 5/5 source-policy unit tests PASS, repo guard failed specifically on missing all-project restore/generate/verify/upload.
- [x] GREEN candidate introduced Python-stdlib CycloneDX v1.5 `project.assets.json` NuGet inventory and nine negative tests. Intermediate [CI 43878060084](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43878060084) exposed policy-fixture order; [CI 43878487858](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43878487858) exposed actual NuGet SDK assets v4, supported explicitly with version v3/v4 guard and new unknown-version denial fixtures.
- [x] [CI 43878993393](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43878993393) backend GREEN: NuGet restore and 9/9 semantic regressions, generated+verified **185** SHA-512-bearing NuGet package occurrences over 9 projects; artifact ID 14231163433, 7-day retention. [Runbook](CI_NUGET_CYCLONEDX_SBOM.md).
- [ ] **Final gate** on documentation-inclusive exact main HEAD: backend/frontend/docker-smoke/terraform all SUCCESS, real PostgreSQL ordinary+full witness restore, Keycloak MFA/PKCE, PWA worker and NuGet/npm SBOM uploads; close only #78 after recorded evidence.
- [ ] Parent #20 remains OPEN for NuGet packages.lock.json/locked mode, complete OCI/native/software provenance/SCA/SAST, vulnerability scans, signed release attestations, PWA mobile installation and cross-tenant API security. #64/#61/#57/#17 and V015/V016 frozen authorization remain unchanged.

## Mobile installability (#80; child #20)

- [x] New ADR 0048 and Playwright Android-Chromium **production build** regression added to docker-smoke CI on main: verifies linked manifest stable root ID, start/scope/display, actual 192/512 PNG signatures/dimensions and maskable declaration; requires controlling Workbox and offline static shell; excluded offline API navigation must not serve a cached SPA, and CacheStorage must contain no API/IdP/health URL. The mobile profile is emulated, not a native OS installation or WORM/qualified evidence.
- [x] TDD RED on [CI 43882463108](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43882463108), exact SHA `154781e`: backend/frontend/terraform SUCCESS, docker-smoke fails **only** at expected missing `manifest.id` (`undefined`, required `"/"`).
- [x] GREEN source: explicit origin-scoped `id: "/"` in Vite PWA manifest with unchanged start and scope. Reproduction and nonclaims in [PWA mobile CI runbook](PWA_MOBILE_INSTALLABILITY_CI.md).
- [ ] #80 closure requires all four CI jobs SUCCESS on exact final GREEN main SHA. Parent #20 stays OPEN for actual device installation, attested artifacts, SAST/secret scans and authenticated cross-tenant API. Security #38/#44/#46/#50/#57/#61/#64, WORM #17 and legal/QTSP #13 all remain OPEN.

## NuGet locked restores (#79, ADR 0049)

- [x] CI-first RED on [43883455966](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43883455966): unit regressions pass while nine missing NuGet locks and mutable restore commands fail source policy.
- [x] Nine genuine NuGet .NET 10 lock files, 62,364 bytes total, recovered from disposable registry-backed CI resolver and committed in `6717fa3` without inventing package versions or hashes.
- [x] Replace seed with all-project `dotnet restore --locked-mode` before backend tests; `--no-restore` test/publish; API Docker and integration tests `RestoreLockedMode=true`; runbook [CI_NUGET_LOCKED_RESTORES.md](CI_NUGET_LOCKED_RESTORES.md).
- [ ] Close #79 only with final-main four-job GREEN, including production mobile PWA #80. Parent #20 and independent security/FIDO/QTSP issues remain OPEN.

## Native Node 24 action runtime selection (#81; child #20, ADR 0050)

- [x] Verified five official upstream version-tag refs **and their exact-SHA action.yml `runs.using=node24`**, including upload-artifact v6 (v5 is still Node20); see [runbook](CI_NODE24_ACTION_RUNTIMES.md).
- [x] **TDD RED** [CI 43887807050](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43887807050), SHA `ac5311f`: 5/5 new offline policy unit tests pass; backend source scan rejects exactly 12 deprecated Node20 action references. Existing mutable SHA guard stays green.
- [x] GREEN: replace all 12 references with immutable reviewed Node24 SHAs, retain four-job job topology, CLI Node22, .NET10, locked NuGet/npm, Keycloak MFA, PWA mobile and full PostgreSQL rollback regression.
- [ ] Close only #81 after **exact final main SHA** all four CI jobs success and review logs for absence of forced Node20 action runtime warnings. #20 and all FIDO, evidence/WORM and signed human consent blockers stay OPEN.

### #81 SBOM dependency-policy integration

- [x] [CI 43888139709](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43888139709) exposed a separate old Node20 SHA literal in the npm SBOM source allowlist; similarly identified NuGet's old literal. New native Node24 action guard was already passing, but first GREEN candidate backend failed at the inherited npm policy.
- [x] Preserve both SBOM source gates, link their allowed upload SHA to the exact upstream-reviewed Node24 allowlist with negative regressions for old Node20 and unknown SHAs. Full exact-head CI verification remains mandatory before closing #81.

## Live two-tenant API HTTP isolation regressions (#82; child #20/#14, ADR 0051)

- [x] Review tenant/auth/DB/PWA ADRs, schema and real CI. Test-first [CI 43892292576](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43892292576): existing backend/frontend/terraform, PostgreSQL witness and Keycloak MFA PASS, new mandatory API harness **RED** precisely at absent real signed Keycloak B principal.
- [x] Add development-only Keycloak principal and access-token org claim fixtures, independent wrong-audience and short-lived signed JWT clients. First fixture [CI 43893706831](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43893706831) reveals account `resolve_required_actions` in Keycloak; complete required demo profile fields.
- [x] Test strict JWT issuer/audience/lifetime distinction (API `ClockSkew=0`), actual PostgreSQL B membership/identity, positive/negative A/B own/cross-tenant list, summary, TSR, ZIP, audit, spoofed selectors, disabled TSA, all no-store and prepared-audit semantics. See [runbook](CI_API_TENANT_HTTP_ISOLATION.md).
- [x] [CI 43897042542](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43897042542) at SHA `dfbbe87`: all four jobs **SUCCESS**; original OIDC empty-registry browser smoke and new two-sided A/B HTTP matrix both PASS in correct order, full PostgreSQL witness rollback, real Keycloak TOTP/PKCE, production PWA mobile and Terraform. **Recheck the final documentation-inclusive main SHA before issue #82 closure.** Production RLS, independently trusted identity, WORM/QTSP and signed reviewer/registrar authorization remain open under parents #20/#14 and #64/#61/#57/#50/#44/#38/#17/#13.

### #82 actual HTTP PASS and fixture sequencing

- [x] [CI 43895442047](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43895442047): full real HTTP A/B isolation matrix PASS, including genuine signed wrong issuer/audience/expired JWT, inactive SQL membership, both sides' ZIP/TSR/audit, selector spoofing, and disabled TSA. Existing *single-tenant empty-registry* browser smoke then fails because new canary A was inserted first.
- [x] Preserve the original empty-registry browser assertion and run it **before** the new disposable canary step; continue running the new real API matrix last before guaranteed Docker teardown. Exact-final-head four-job CI remains required before #82 closure.

## Delegated TSA transport hardening (#83; parent #15 remains open)

- [x] ADR 0052 and RED-first .NET 10 negative transport tests: no implicit redirect/cookie handling in the named TSA HttpClient; every 301/302/303/307/308 provider response rejected.
- [x] Dedicated handler wired to `external-tsa` API registration on `main`; server-owned HTTPS endpoint, 20-second timeout and `Unverified` persisted state unchanged. [Transport runbook](TSA_HTTP_TRANSPORT.md).
- [x] #83 closed after verified exact final `main` SHA `c7c48bdebbc164785eac6bc73ee7c9678796553d` four-job [GREEN CI 43899567218](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43899567218); parent #15 OPEN.
- [ ] Parent #15 remains OPEN for complete signed RFC3161 / CMS / historical EU Trusted List, revocation, network egress allowlists, tested QTSP interoperability and legal status checks; WORM #17 and legal qualification #13 likewise remain OPEN.

### CI API isolation closeout (#82)

- [x] #82 closed after four-job GREEN on exact `main` SHA `dfbbe87fdc2506afc5763ecce95cad398e4a147a`: [Actions run #391](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43897042542). Production RLS and broader tenant management remain #14/#20.

## RFC 3161 HTTP response envelope (#84; child of #15; ADR 0053)

- [x] Re-read ADR 0002/0052, real provider and transport runbook; record strict 200-only (local policy) + exact `application/timestamp-reply` response MIME requirement, including RFC 3161 §3.4 verified erratum 1879 in [ADR 0053](../adr/0053-rfc3161-strict-http-response-envelope.md).
- [x] RED-first [CI 43902202323](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43902202323) at `869f61c3`: 10 targeted tests FAIL for premature body read on 201/202/204/206 and missing/wrong MIME; existing .NET business/domain tests and other provisioning tests PASS.
- [x] Provider-only GREEN candidate: reject non-`200 OK` and wrong/missing `Content-Type` *before* reading DER. Preserve RFC3161 nonce/imprint/CMS check, 1 MiB cap, no redirect/cookies, HTTPS and `Unverified` semantics. Runbook: [TSA_HTTP_TRANSPORT.md](TSA_HTTP_TRANSPORT.md).
- [x] #84 closed after exact-main four-job [GREEN CI 43902761373](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43902761373), SHA `997fd035df7e102a024f001ed623767b1269cd71`. Parent #15/#17/#13 remain OPEN.

## RFC 3161 provider endpoint authority / development loopback (#85; child #15; ADR 0054)

- [x] Re-read ADR 0002/0052/0053, actual provider/API, threat model and transport runbook; record fail-closed syntax/loopback decision in [ADR 0054](../adr/0054-rfc3161-endpoint-uri-development-loopback.md).
- [x] RED-first [CI 43904739193](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43904739193), SHA `9150a18a`, backend compiler CS1739 for missing dedicated `allowDevelopmentLoopback` on real-provider tests. Existing 9 domain + 219 business passed; Terraform green.
- [x] Central `ExternalRfc3161EndpointPolicy` and provider default reject untrusted URI scheme/userinfo/fragment, HTTPS loopback and literal IP without an explicit flag; API injects that flag only from `IHostEnvironment.IsDevelopment`. [Runbook](TSA_HTTP_TRANSPORT.md). This is **not** DNS-binding, network egress or QTSP trust validation.
- [x] #85 closed after exact-main four-job [GREEN CI 43905297835](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43905297835), SHA `fab01d607fdbe0f6abf298ed1e38be42a1b55b9d`; parent #15/#17/#13 remain OPEN.

## RFC 3161 TSA client ambient forward-proxy bypass (#86; child #15, ADR 0055)

- [x] Reviewed ADR 0002/0052/0053/0054, threat model, operator runbook, dedicated `external-tsa` named HTTP handler and Microsoft .NET 10 default proxy behavior; record [ADR 0055](../adr/0055-rfc3161-no-ambient-forward-proxy.md) before code.
- [x] **TDD RED** [CI 43907504241](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43907504241), test-only SHA `47f0d5c`: two new proxy-negation tests FAIL on actual handler `UseProxy=true`; third new handler test and all prior suites pass (183 provisioner, 219 business, 9 domain).
- [x] GREEN candidate: set `UseProxy=false` only in the named outbound TSA handler. Continue no redirect/cookies, 20-second timeout, strict 200/MIME, endpoint preflight, bounded DER verification and `Unverified` state. Document direct egress/firewall requirement and no implicit `HTTPS_PROXY` support in [TSA_HTTP_TRANSPORT.md](TSA_HTTP_TRANSPORT.md).
- [x] #86 closed after final exact-main four-job [GREEN CI 43907974158](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43907974158), SHA `f1df57c19f5883c287ae436fb84a411d862614ad`; parent #15/#17/#13, network egress/DNS issues remain OPEN.

## RFC 3161 connection-time DNS/IP denial + socket pinning (#87, child #15; ADR 0056)

- [x] Re-read ADR 0002/0052–0055, real `external-tsa` HTTP factory/provider, threat model and runbook. Confirm .NET 10 `SocketsHttpHandler.ConnectCallback`, DNS and Socket APIs; record [ADR 0056](../adr/0056-rfc3161-connect-time-resolved-destination-policy.md) **before implementation**.
- [x] **TDD RED** [CI 43911461382](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43911461382), SHA `e1e4182b`: tests-first backend compile fails exactly due absent resolved-destination policy, callback and explicit Development-only loopback flag; domain 9/9, business 219/219, frontend and Terraform pass.
- [x] **GREEN candidate** [CI 43912053272](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43912053272) at `04a59817`: 9 domain, 219 business and 229 provisioner = **457 tests passing**, including 44 new IPv4/IPv6, mixed/empty DNS, no-implicit-proxy/redirect, real-loopback-TCP regressions. Handler now resolves once per **new socket**, validates all IP addresses before dialing, then connects by approved IP without another hostname resolution. Existing `UseDefaultCredentials`-specific test updated to Sockets handler `Credentials` semantics; only `external-tsa` affected. [Transport guide](TSA_HTTP_TRANSPORT.md).
- [x] #87 **closed** after final exact-main [CI 43912615969](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43912615969), SHA `9ac9fc61cf7d3e1ab35cfd3836557152c7ba0ed7`, 4/4 GREEN and 457 passing .NET tests. Parent #15, WORM #17 and legal #13 remain OPEN; public-IP DNS spoofing and operator-approved egress/IP/service allowlisting still need production controls.

## RFC 3161 short-lived TSA connection pool and TLS1.2+ negotiation (#88; child #15, ADR 0057)

- [x] Reviewed ADR 0002/0052–0056, live named `external-tsa` transport provider/API and tests, `docs/THREAT_MODEL.md` and `docs/TSA_HTTP_TRANSPORT.md`. Documented [ADR 0057](../adr/0057-rfc3161-bounded-connection-lifetime-and-tls-floor.md) **before code** based on official .NET 10 `SocketsHttpHandler.PooledConnectionLifetime` and `SslProtocols` contract.
- [x] **TDD RED:** [CI 43915676967](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43915676967), test-only commit `763f124e`: 4 specific new xUnit checks FAILED for infinite pooled lifetime and implicit OS TLS negotiation (including both Development flag variants); 231 other provisioning tests, 219 business and 9 domain passed. No test harness/compiler errors.
- [x] GREEN candidate: only `ExternalRfc3161TransportPolicy.CreateHandler` adds `PooledConnectionLifetime=60s` and `SslOptions.EnabledSslProtocols=TLS1.2|TLS1.3`. Preserve normal TLS certificate/hostname validation (callback null), no proxy/redirect/cookies, original DNS callback and Development-only localhost. Update operator [runbook](TSA_HTTP_TRANSPORT.md), threat model and roadmap. Existing .NET 10 tests and real Keycloak/PostgreSQL smoke must continue passing.
- [x] #88 closed after exact final-main four-job [CI 43916214609](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43916214609), SHA `6b25d7bd3d021707ad44f5ad5263d5088f6a73de`: backend/frontend/docker-smoke/terraform all GREEN and 463 .NET tests passing. Parent #15 and #17/#13 remain OPEN.

## RFC 3161 signing certificate critical single-purpose EKU (#89; child #15; ADR 0058)

- [x] Re-read ADR 0002/0052–0057, real `ExternalRfc3161TimestampProvider` and tests, threat model and TSA runbook. Verify [RFC 3161 §2.3](https://www.rfc-editor.org/rfc/rfc3161#section-2.3) **exactly one CRITICAL EKU extension solely `id-kp-timeStamping`** (OID 1.3.6.1.5.5.7.3.8); .NET verifier requires EKU presence but doesn't document sole critical extension guarantee. Record [ADR 0058](../adr/0058-rfc3161-critical-exclusive-timestamp-signer-eku.md) before tests/code.
- [x] **TDD RED** [CI 43919547198](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43919547198), test-only SHA `778bf077`: missing signer EKU policy CS0103, 9 domain + 219 business tests PASS. Disposable self-signed fixture cases: exact critical-only EKU, no signer, missing/noncritical EKU, wrong/multiple/any-purpose, malformed DER and duplicate extension.
- [x] GREEN implementation candidate: `ExternalRfc3161SignerCertificatePolicy` enforces exactly one critical EKU extension and only one timeStamping OID on **the certificate returned by verified token signature**, before any provider result; provider only returns generic rejection and preserves `Unverified` pilot status. Regression first detected `CertificateRequest` itself blocks duplicate EKU extensions [CI 43919890263](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43919890263) (248/249 provisioning cases passed); added **explicit DER-only synthetic duplicate-extension fixture**, without claiming valid certificate signature or QTSP trust.
- [x] #89 closed after final exact-main [CI 43920557678](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43920557678), SHA `1906437f615cf0f03797890ab54cc08fe6747edd`, **4/4 GREEN and 477 .NET tests passing**. Parent #15, WORM #17 and legal #13 remain OPEN.

## RFC 3161 mandatory operator-approved CMS signer SHA-256 DER fingerprint (#90; child #15, ADR 0059)

- [x] Re-read ADR 0002/0052–0058, `docs/TSA_HTTP_TRANSPORT.md`, `docs/THREAT_MODEL.md`, provider, named API DI and endpoint/MIME/redirect tests. Confirm that the actual cryptographically verified RFC3161 CMS signer is **not bound to an operator-reviewed identity**, regardless of correct signed nonce/imprint or critical EKU; document [ADR 0059](../adr/0059-rfc3161-operator-approved-signer-certificate-sha256.md) **before code**.
- [x] **TDD RED** [CI 43927346733](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43927346733), tests-only `main` SHA `a3e06c8615e7d9d51ec5081b1ec762a3b547c93b`: 12 expected missing policy / constructor compile errors; domain 9/9 and business 219/219 passed, Terraform green. Test generated disposable self-signed certs for approved/unapproved SHA-256 DER signer binding, absent/malformed/ambiguous/no-pin HTTP preflight.
- [x] GREEN implementation: `ExternalRfc3161SignerPinPolicy` rejects any non-64-ASCII-hex whole DER SHA-256 pin before a network send; `ExternalRfc3161TimestampProvider` checks the *actual verified CMS signer* using `X509Certificate2.GetCertHash(HashAlgorithmName.SHA256)` and constant-time comparison **after** signature, nonce, imprint and sole critical EKU. `Program.cs` supplies only server-owned `TimestampProvider:SignerCertificateSha256`; appsettings template exposes blank intentionally; no tenant override, no TOFU, no SHA-1 `Thumbprint`, and disabled TSA still works unconfigured. Existing endpoint, redirect and MIME regression fixtures explicitly supply a valid dummy-format pin to retain their original assertions. [Operator runbook](TSA_HTTP_TRANSPORT.md) covers offline cert approval and planned leaf rotation.
- [x] Intermediate [CI 43928141374](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43928141374) failed only one targeted test, which accidentally treated a generic error-message **space** as disclosure of a single-space malformed pin; fixed the fixture expectation (do not hide any real pin). **GREEN backend candidate** [CI 43928307645](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43928307645) passed **9 domain + 219 business + 276 provisioning = 504 tests**.
- [x] #90 closed after [exact-main 4/4 GREEN CI 43929078394](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43929078394), SHA `d78637bfcc9a96278e258360a26bc4cf7afb33ec`, 504/504 .NET tests, full real Docker Keycloak/PostgreSQL/two-tenant HTTP smoke. Parent #15, WORM #17 and legal #13 remain OPEN; SHA-256 leaf pin does not establish qualified chain trust.

## RFC 3161 reviewed TSA service policy reqPolicy/TSTInfo binding (#91, child #15; ADR 0060)

- [x] Reviewed ADR 0002, ADR 0052–0059, `docs/TSA_HTTP_TRANSPORT.md`, `docs/THREAT_MODEL.md`, real provider/API DI and redirect/response/endpoint/pin tests. [RFC3161 §2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2) requires requested `TimeStampReq.reqPolicy` to match signed `TSTInfo.policy`. Existing provider persisted arbitrary token policy under a pinned signer. Recorded [ADR 0060](../adr/0060-rfc3161-operator-approved-request-and-signed-token-policy.md) before code.
- [x] **TDD RED** [CI 43931749155](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43931749155), tests-only `main` SHA `6391bb4e8dc6eb996169a9ef85c9d77b3cd908d7`: expected missing policy-validator symbols (CS0103) and missing `approvedPolicyOid` provider named parameter (CS1739); 9 domain, 219 business, frontend/Terraform passed. No qualification claim.
- [x] GREEN: `ExternalRfc3161ApprovedPolicy` parses only canonical dotted-decimal operator-approved OID; missing, invalid, ambiguous or oversized config is rejected **before HTTP send**. The real request includes `requestedPolicyId`; the provider explicitly compares signed token policy to expected after CMS/imprint, EKU and verified SHA-256 signer pin, before returning evidence. API injects `TimestampProvider:PolicyOid` only from operator configuration; template leaves empty until reviewed. No development/tenant bypass, no fallback. Existing MIME/status/redirect/endpoint/pin fixtures explicitly use **dummy syntax-valid** policy to retain original assertions. Actual spy-HTTP RFC3161 DER request regression checks `RequestedPolicyId`, SHA-256 imprint, nonce, certReq. Updated [operator guide](TSA_HTTP_TRANSPORT.md) and threat model.
- [x] Backend [GREEN CI 43932390882](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43932390882), SHA `39c3efe227c333caf4c2a7af79f76c9593df8188`: 9 domain + 219 business + **318 provisioner = 546/546 .NET tests** pass. Earlier intermediate runs failed only existing endpoint/MIME/redirect/pin tests not yet supplied with mandatory test policy; addressed before final.
- [x] #91 closed after final exact-main four-job [CI 43932888329](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43932888329), SHA `20aa26f07a90b734cc01c9b5b4166d150e7dc63d`, **546 .NET tests**, real Keycloak MFA/PostgreSQL/tenant HTTP integrations 4/4 GREEN; parent #15, WORM #17 and legal #13 remain OPEN.

## RFC 3161 operator-approved offline X.509 CA path for verified signer (#92; child #15; ADR 0061)

- [x] Consulted ADR 0002, ADR 0052–0060, `docs/TSA_HTTP_TRANSPORT.md`, `docs/THREAT_MODEL.md`, current provider/API and signer EKU/pin/policy tests. Verified .NET 10 `Rfc3161TimestampToken.AsSignedCms().Certificates`, `X509ChainPolicy.TrustMode=CustomRootTrust`, `CustomTrustStore`, `ExtraStore`, `DisableCertificateDownloads`. Documented [ADR 0061](../adr/0061-rfc3161-operator-approved-offline-signer-x509-chain.md) **before test/code**.
- [x] **TDD RED** [CI 43942439055](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43942439055), tests-only main SHA `745a5853adaa49a12061dfcb1cb39b1516747bc3`: backend expected 20 missing offline chain policy symbols (CS0103) + 2 missing provider constructor args (CS1739); domain 9/9, business 219/219, frontend/Terraform green.
- [x] GREEN implementation: new `ExternalRfc3161CertificateChainPolicy` parses exactly one canonical Base64 DER self-issued CA root with critical CA BasicConstraints/KeyCertSign **before HTTP**, failing if absent/invalid; provider uses X509Chain on the *verified* CMS signer with **only custom reviewed root** and intermediates from the signed CMS. `DisableCertificateDownloads=true`, `VerificationFlags=NoFlag`, `VerificationTime=DateTime.UtcNow`, **`RevocationMode=NoCheck` explicitly**. No OS-root fallback, no AIA/CRL/OCSP automatic fetch, no historical qualified trust claim. API-only `TimestampProvider:TrustAnchorCertificateBase64Der` setting and blank appsettings template. On-prem/Azure same functionality. Existing HTTP regression fixtures now use a **disposable test-only RSA root CA**; added root→leaf, root→intermediate→leaf positive/negative, wrong root, expired leaf, non-CA or malformed root, untrusted signer, tampered signature, and pre-send failure checks.
- [x] Backend initial [GREEN candidate CI 43943120379](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43943120379), SHA `367719c8487fb228160983e920dc4fd4511a1f07`, passed **9 domain + 219 business + 343 provisioner = 571 .NET tests**. Additional explicit tampered-CA-signature regression added afterward. Updated [TSA operator runbook](TSA_HTTP_TRANSPORT.md) and threat model; declared **signing-time revocation / historical Trusted Lists NOT IMPLEMENTED**.
- [x] #92 closed after **exact final-main** SHA `e27921e0dae54d6cd3aa4925c7300830ad41fede` on [4/4 GREEN CI 43943927392](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43943927392): 9 domain + 219 business + 344 provisioning = **572 .NET tests**; real Keycloak MFA, PostgreSQL full restore and two-tenant signed HTTP smoke passed. Parent #15, WORM #17 and legal #13 remain OPEN; CRL/OCSP and historical EU Trusted List qualifications are not implemented.

## RFC 3161 bounded live signed `genTime` and issuance-time X.509 validity (#93; child #15, ADR 0062)

- [x] Reviewed ADR 0002/0052–0061, docs TSA HTTP/threat/roadmap, actual provider/custom-root X509 chain and test fixtures. Verified [RFC3161 §2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2) defines signed UTC `genTime`, and [Microsoft X509ChainPolicy.VerificationTime](https://learn.microsoft.com/en-us/dotnet/core/compatibility/cryptography/7.0/x509chainpolicy-verification-time) supports explicit certificate-validity time. Documented [ADR 0062](../adr/0062-rfc3161-live-gen-time-and-issuance-time-x509-path.md) **before tests/code**; this is a live-window plausibility control, NOT UTC(k) or legal timestamp qualification.
- [x] **TDD RED** tests-only SHA `e8154d3b7915349b54e91ce2f563b93017bb2158` [CI 43956887816](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43956887816): intended CS0103 missing issuance-time policy, CS1501 missing explicit time overloads; existing 9 domain/219 business passed. New regressions cover inclusive ±120s window around real HTTP interval, signed time too stale/future, clock reversal, timezone-offset invariance, extreme invalid dates, and X509 certificate chain at **signed issuance instant** rather than current wall-clock.
- [x] GREEN implementation: `ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime` rejects out-of-window CMS-signed `TSTInfo.genTime` and reversed wall clock. Real `ExternalRfc3161TimestampProvider` captures `requestStartedAt` immediately before `HttpClient.SendAsync`, `responseReceivedAt` after reading the complete bounded reply; only after CMS/nonce/imprint/EKU/signer DER SHA-256 pin/reqPolicy verifies the signed `genTime`, then passes exactly that DateTimeOffset to `ExternalRfc3161CertificateChainPolicy.ValidateSignerChain`. Chain `VerificationTime` is explicitly `signedIssuanceTime.UtcDateTime` (not implicit today). No OS CA fallback, AIA downloads, unsafe redirects or tenant timing inputs. Existing root→leaf, root→intermediate, wrong-root, signature tamper tests now supply explicit verification time; missing revocation and historical qualification remain unresolved.
- [x] **GREEN backend candidate** [CI 43957506994](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43957506994) on SHA `eda88934b6bbb1a493dd4bcf69b158064c0d12fd`: **9 domain + 219 business + 367 provisioning = 595 .NET tests passed**; frontend and terraform also green. Operator [runbook](TSA_HTTP_TRANSPORT.md) and [threat model](THREAT_MODEL.md) document NTP/UTC drift, 120s pilot tolerance, no certified accuracy or revocation.
- [x] #93 closed after exact final-main SHA `aba3bd4435d9afcdf77e7f83680b5a781b63c30d` on [4/4 GREEN CI 43957985658](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43957985658): 9 domain + 219 business + 367 provisioning = **595 tests**; real Keycloak TOTP/PKCE, PostgreSQL full restore and two-tenant HTTP smoke passed. Parent #15/#17/#13 remain OPEN for historical revocation, EU Trusted Lists, WORM and legal verification.

## RFC 3161 independently signed complete issuer CRL for direct CA root→TSA signer (#94; child #15; ADR 0063)

- [x] Reviewed ADR 0002/0052–0062, operator TSA runbook, threat model, roadmap, actual `ExternalRfc3161TimestampProvider`, X509 custom-root validator and test fixtures. [RFC5280 §5.1/§6.3](https://www.rfc-editor.org/rfc/rfc5280#section-5.1) defines signed complete CRL issuer/signature, CRLNumber, AKI, `thisUpdate/nextUpdate` and serial revocation; .NET 10 `CertificateRevocationListBuilder.Build` generates genuine issuer-signed disposable RSA CRLs. Recorded [ADR 0063](../adr/0063-rfc3161-offline-direct-issuer-signed-full-crl.md) **before code**; do not confuse X509Chain `NoCheck` path validation with true revocation checking.
- [x] **TDD RED** [CI 43961838074](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43961838074), tests-only `main` SHA `7ba52b4bec7d9fdd7c78cb4b88cf56189546816a`: 13 intentional missing `ExternalRfc3161IssuerCrlPolicy` and 2 missing provider named-arg errors (CS0103/CS1739); 9 domain/219 business, frontend and Terraform GREEN. Tests cover genuinely signed clean/revoked/altered RSA CRLs, wrong issuer with same DN, freshness, trailing/noncanonical DER and pre-send missing CRL, multi-hop rejection.
- [x] GREEN implementation: new `ExternalRfc3161IssuerCrlPolicy` requires canonical ≤1 MiB full DER CRL from **operator-owned `TimestampProvider:IssuerCrlBase64Der`** before HTTP. Parse RFC5280 v2 complete CRL, verify **outer/inner RSA SHA-256 algorithm match**, full issuer DER DN and root `CrlSign`/AKI-SKI, root-public-key signature over original `TBSCertList`, `thisUpdate ≤ signed genTime < nextUpdate`, and no matching verified CMS signer serial among revoked entries. Reject unknown CRL extensions/delta/indirect and **all multi-hop chains** since one root CRL cannot establish intermediate and leaf revocation. API-only setting and blank `appsettings.json`; Azure/on-prem parity, no CRL/AIA web fetching, no tenant-supplied override. Existing HTTP test fixtures supplied with disposable real root+CRL pair; full provider validates after signature/imprint/nonce/EKU/SHA256 signer pin/policy/live signed genTime and custom-root path.
- [x] An intermediate compilation [CI 43962713301](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43962713301) reported only a C# fixture type inference error when injecting a trailing DER byte (CS9174); explicitly typed the byte array. **GREEN backend candidate** [CI 43962983877](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43962983877), SHA `0a6757f2b2f96732a8a86f8c212affaa1465d3f4`: **9 domain + 219 business + 389 provisioning = 617 .NET tests passing**. Updated [operator runbook](TSA_HTTP_TRANSPORT.md) and [threat model](THREAT_MODEL.md) with CRL signature, complete/scope caveats, freshness and manual authenticated CRL rollover.
- [x] #94 closed after [final exact-main 4/4 GREEN CI 43963576300](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43963576300), SHA `1b9317cc49356406759adfffd1e5acc696cdc6de`, **617 .NET tests** plus real Keycloak/TOTP/PKCE and PostgreSQL backup/restore/two-tenant HTTP isolation. Parent #15, WORM #17, legal #13 remained OPEN; qualified historical Trusted Lists, partial-scope CRL/OCSP and CRL evidence retention incomplete.

## RFC3161 signed CRL coverage for root→intermediate CA→TSA signer (#95; child #15; ADR 0064)

- [x] Re-read ADR 0002/0052–0063, `docs/TSA_HTTP_TRANSPORT.md`, threat model and roadmap, actual RFC3161 provider/PKIX root path and CRL validator, API/config and disposable root/intermediate/signer+signed-CRL tests. Confirmed [RFC5280 §6.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.3) requires status proof for each non-root path element and [RFC10007](https://www.rfc-editor.org/rfc/rfc10007.html) mandates CRL issuer `cRLSign`. Documented [ADR 0064](../adr/0064-rfc3161-intermediate-issuer-complete-crl-coverage.md) **before tests/code**.
- [x] **TDD RED** [CI 43965945739](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43965945739) on tests-only `main` SHA `248a61ee2afccb9ef8610ffa2d79a1a0a914b0ba`: expected missing selected-path revocation validator, validated chain builder, and provider named setting; domain 9/9, business 219/219, frontend and Terraform GREEN. Corrected a test-only unsupported two-argument `X509Certificate2Collection` constructor (CS1729).
- [x] Implemented `ExternalRfc3161CertificateChainPolicy.BuildValidatedSignerChain`: caller-owned already-valid custom-root `X509Chain` anchored to exact reviewed DER root and cryptographically verified CMS signer, intermediates only in CMS, no AIA/OS fallback; old `ValidateSignerChain` uses/disposes it. `ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation` accepts only verified **2/3-element** path, requiring root-signed full CRL for the root's direct child and, for the 3-element path, **second signed complete CRL from actual intermediate CA** for verified TSA leaf. Reject revoked intermediate, revoked signer, stale/unsigned/wrong-key issuer CRL, missing second CRL or longer chains; direct-root path still uses root CRL only (explicitly rejects an unused second CRL). No partial revocation bypass.
- [x] Server-owned `TimestampProvider:IntermediateIssuerCrlBase64Der` optional for direct path; **any nonempty malformed/unsupported CRL denied before outbound TSA HTTP**. API DI, blank appsettings and on-prem/Azure parity updated. Tests use real disposable RSA root/intermediate/leaf certs and **two genuinely issuer-signed CRLs**; added wrong-key same-DN CMS impostor, expired/not-yet-effective CRLs, missing CMS intermediate, invalid config, direct-path parity, and **fail-closed** handling of a synthetic longer path with more than one intermediate (whether X.509 path building or the two-CRL gate rejects first). Updated [TSA runbook](TSA_HTTP_TRANSPORT.md) and [threat model](THREAT_MODEL.md).
- [x] Backend **GREEN candidate** [CI 43966530774](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43966530774), SHA `2b35a3ebc2297eb31f93f2758921c59b1f9e286b`, passed **9 domain + 219 business + 402 provisioner = 630 .NET tests**. One further >1-intermediate negative test added afterward, which requires exact final CI verification.
- [x] #95 **closed** on exact docs-inclusive `main` SHA `f38e7e27882410fdc19ae305b58ea2cb79ac44f7` [CI 43967638799 4/4 GREEN](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43967638799): 9 Domain + 219 Business + 403 Provisioner = **631 tests**, plus real PWA, PostgreSQL restore, Keycloak TOTP/PKCE, signed two-tenant HTTP smoke and Terraform. Parent #15/#17/#13 remained OPEN.

## RFC3161 signed CRLNumber operator-reviewed minimums per issuer (#96; child #15; ADR 0065)

- [x] Reviewed ADR 0002/0052–0064, docs TSA operator runbook/threat/roadmap, actual `ExternalRfc3161IssuerCrlPolicy` DER parser, provider/API and direct/two-hop genuinely signed CRL fixtures. Confirmed [RFC5280 §5.2.3](https://www.rfc-editor.org/rfc/rfc5280#section-5.2.3): a mandatory **noncritical signed CRLNumber** increases per issuer/scope (support up to 20 octets). Committed [ADR 0065](../adr/0065-rfc3161-operator-crl-number-minimum-floors.md) **before code**. This is a **deployment-managed static floor**, *not* an independently witnessed monotonic CRL log.
- [x] **TDD RED** tests-only `main` SHA `c11665a654a7eaeb1ffa13c60f353080680108f9` [CI 44009723455](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44009723455): missing `ParseRequiredCrlNumberFloor`, signed issuer CRL number floor parameter and provider config caused only the expected CS0117/CS1739 errors; prior 9 Domain / 219 Business passed. New genuinely issuer-signed CRLs numbered 1, 2, 4 and 2^80 cover equal vs lower/higher CRLNumber floor, independent root/intermediate issuer floors, very large numbers, malformed/missing/noncanonical config pre-send, no unused intermediate floor, disabled TSA.
- [x] GREEN implementation: `ExternalRfc3161IssuerCrlPolicy` preserves signed CRLNumber, rejects negative/oversized (>20 unsigned octets) or critical AKI/CRLNumber, parses strict canonical positive decimal operator floor via `BigInteger`, and compares each issuer's **authenticated** signed CRLNumber against **that issuer's own floor** during full signature/freshness/serial validation. `ExternalRfc3161TimestampProvider` requires server-owned root floor and conditionally required intermediate floor **before HTTP**; disabled TSA remains unchanged. Azure/on-prem API configuration `TimestampProvider:IssuerCrlNumberFloor` and `TimestampProvider:IntermediateIssuerCrlNumberFloor` present blank by default. Updated prior HTTP transport/response/pin tests with disposable approved signed CRLNumber=1/floor=1 to preserve original assertions.
- [x] [Operator runbook](TSA_HTTP_TRANSPORT.md) and [threat model](THREAT_MODEL.md) updated: operator must independently authenticate and monotonically advance both CRL floors, preserve approvals and prevent config rollback. Old signed CRLs with numbers below floor fail, but **rolling back both static floor and CRL still defeats this control**. This is NOT production evidence retention, legal qualification, historic QTSP EU Trusted List status, UTC(k) or independent last-seen witness.
- [x] #96 **closed** after GitHub issue confirms exact final docs-inclusive `main` SHA `44bb7583b14c5ee43a24149d19d7e0815f3c123b`, [final CI 44010513402](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44010513402) **4/4 SUCCESS** (backend/frontend/docker-smoke/terraform), **668/668 .NET tests**. This verified result applies only to #96's then-final SHA, NOT to subsequent #97/#98 changes. #15/#17/#13/#20 remain OPEN; records remain Unverified.

## RFC3161 signer end-entity/Key Usage pilot gate (#97; child of #15)

- [x] ADR 0066 reviewed and committed **before** source/test changes.
- [x] New xUnit tests **committed RED-first** to main (missing implementation class at commit `9a51ccb`); disposable signed certificate fixtures exercise valid non-CA signature Key Usage and fail-closed missing/CA/malformed/duplicate/non-signing/key-sharing extensions. RED CI result has **not** yet been independently confirmed.
- [x] GREEN-path implementation of isolated `ExternalRfc3161TsaLeafProfilePolicy` and invocation after cryptographically identified CMS signer and critical sole EKU. No SQL, Keycloak or WebAuthn changes, or qualification claims.
- [x] Same Azure/on-prem behavior; documented deliberate strict end-entity interoperability profile and residual limitations in TSA_HTTP_TRANSPORT / ADR 0066.
- [ ] Confirm exact **final documentation-inclusive main HEAD** four-job backend/frontend/terraform/docker-smoke GitHub Actions SUCCESS, then close only #97 and record links/commit evidence. Parent #15, WORM #17 and legal #13 remain OPEN; receipt state stays **Unverified**.

## Strict signed TSTInfo accuracy filter (#98; child of #15, ADR 0067)

- [x] Reviewed ADR 0002, 0058–0066 and RFC3161 optional TSTInfo.accuracy semantics, .NET 10 nullable microseconds property, actual provider/signed time policies and docs. ADR 0067 committed **first**, before tests or code: `6cc2d011e8ef4284da7cd016b3c2e4ff22ee2afe`.
- [x] RED-first xUnit on main commits `e5c4fda`/`5bc88a4` cover present 0..1,000,000us inclusive, missing/negative/out-of-range/huge claims, and a genuine DER TSTInfo encode/decode path with `AccuracyInMicroseconds`. The synthetic TSTInfo **does not have a CMS signature**; RED runner outcome remains **unverified**.
- [x] Implemented independent `ExternalRfc3161SignedAccuracyPolicy` (`615a121`) and actual use on the already signature/imprint/nonce/signer/path/CRL/live-time verified token (`dfdeea9`); generic failure for absent/bad claim before persisted result. No new settings or migrations; equal behavior on Azure/on-prem.
- [x] Operator TSA runbook and threat model document that a claimed one-second `accuracy` is **not** independently measured UTC(k), a legal qualification threshold or real QTSP status. RFC 3161 allows the field to be absent if accuracy is described by authenticated TSA policy: strict pilot rejects such receipts pending a new reviewed decision. All records remain `Unverified`.
- [ ] Verify **exact final documentation-inclusive main HEAD** 4/4 GitHub Actions jobs and backend tests, record success/fail evidence, close only #98 if green; #97 also stays OPEN pending separately verified evidence, #15/#17/#13 remain OPEN.

## RFC3161 fail-closed I/O failure on streamed TSA body (#99; child #15, ADR 0068)

- [x] Reviewed ADR 0002, 0052–0067, HTTP `ResponseHeadersRead` / `HttpContent.ReadAsStreamAsync` implementation, status/MIME regressions and API provider exception paths; recorded [ADR 0068](../adr/0068-rfc3161-response-stream-io-fail-closed.md) first on `main` SHA `dc135237`. This is a resilience/error-boundary improvement, **not** timestamp legal verification.
- [x] RED-first xUnit regression committed SHA `ca5f382`: with real disposal-only root+signed CRL fixture and properly configured fake TSA, send-time IOException, response-stream acquisition IOException and **partial DER then IOException** must expose only generic `TimestampProviderUnavailableException`; malformed complete DER remains a response error; explicit caller cancellation is not turned into a success. Actual RED GitHub Actions result **not independently verified**.
- [x] Minimal provider catch maps `IOException` to generic unavailability (SHA `4d87756`), preserving existing 1 MiB response limit, HTTP envelope, RFC3161 CMS/imprint/nonce, full PKIX+issuer CRL, strict leaf profile and signed claimed accuracy gates. Same on-prem/Azure behavior, no new tenant/SQL/WebAuthn privileges, no QTSP claim.
- [x] Operator transport runbook and threat model describe partial responses and the **upstream may have issued anyway** unknown-commit/retry/idempotency risk. No unsafe automatic retry.
- [ ] Verify final **documentation-inclusive main HEAD** backend/frontend/docker-smoke/terraform **4/4 SUCCESS** and record real test counts before closing only #99. #97/#98 pending verified CI also remain OPEN. Parents #15/#17/#13 remain OPEN; all pilot records `Unverified`.

## RFC3161 strict signed TSTInfo extension interoperability gate (#100; child #15, ADR 0069)

- [x] Audited ADR 0002/0058–0068, actual RFC3161 provider, signed-accuracy gate and .NET DER TSTInfo APIs, TSA operator guide/threat/roadmap. RFC3161 §2.4.2 has optional TSTInfo extensions; its §2.4.1 TSA unknown-request-extension rule **must not be conflated** with a universal client response-extension prohibition. [ADR 0069](../adr/0069-rfc3161-signed-tstinfo-extension-interoperability.md) committed first SHA `f00a77e`.
- [x] RED-first genuine .NET `Rfc3161TimestampTokenInfo.Encode/TryDecode` tests SHA `75cc860`, regression fixture fix SHA `214797c`: optional extensions absent accepted, one critical or noncritical extension and mixed extensions rejected, null token denied. The TSTInfo is DER but **unsigned** and therefore not legal/QTSP evidence; actual GitHub RED runner status **not retrieved**.
- [x] Minimal policy `ExternalRfc3161TstInfoExtensionPolicy` SHA `249e4e1` and invocation on actual verified CMS token in `ExternalRfc3161TimestampProvider` SHA `240c47e`. Any nonempty signed TSTInfo extension set fails closed after all existing signer/KU/EKU/pin, policy, nonce/imprint, time, CRL and accuracy controls and before provider result. Same Azure/on-prem behavior, no tenant configuration, no SQL permissions.
- [x] Operator runbook and threat model explain this is a **strict pilot interoperability policy**, not a universal RFC3161 client mandate; legitimate QTSP extensions require operator-approved semantics and a follow-up ADR. No qualified status. All records `Unverified`.
- [ ] Check exact **latest docs-inclusive main SHA** and actual **four successful CI jobs** backend/frontend/docker-smoke/terraform; close #100 only if verified. Prior #97/#98/#99 continue OPEN pending their own exact-head CI evidence. Parent #15/#17/#13 remain OPEN.
