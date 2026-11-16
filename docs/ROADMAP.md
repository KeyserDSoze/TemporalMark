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
- Final closure gate: [issue #77](https://github.com/KeyserDSoze/TemporalMark/issues/77) records the exact `main` SHA and **all four** CI results, including real PostgreSQL backup/restore, PWA, Keycloak MFA and Terraform; do not close child until verified.
- [ ] #20 remains OPEN: .NET/NuGet and OCI/system-wide SBOM, actual security scanning/SCA/SAST, publisher signatures, runner attestation, signed release provenance, long-term evidence retention, mobile PWA installation and authenticated cross-tenant tests. No #64/#61/#57/#17 or V015/V016 release-blocker changes.
