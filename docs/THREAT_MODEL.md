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

## Exact WebAuthn raw signature-message boundary (#43, ADR 0020)

A forged browser response may pass all prior unsigned JSON, RP hash, UP/UV and counter preflights. The non-authorizing `ReviewerWebAuthnUnsignedAssertionTranscript` now combines **original** 37-byte basic `authenticatorData || SHA256(original clientDataJSON)` into a fresh 69-byte byte-for-byte buffer; different JSON ordering/BOM changes the message, as a genuine signature verifier would observe. No normalized/constructed JSON is substituted for original signed bytes. This method makes NO cryptographic signature or reviewer possession claim: a malicious browser can build the entire transcript itself. It never grants privilege, consumes a challenge or changes an enrollment. Future #38 MUST use a maintained verifier against an independently approved registered public key, check live IdP role, UV, original scope/action/challenge/expiry, credential counter, one-time transactional decision and revocation of the old direct SQL reviewer decision grants. See [ADR 0020](../adr/0020-webauthn-unsigned-signing-transcript.md) and [operator guide](WEBAUTHN_TRANSCRIPT.md). WORM/QTSP #17/#13 remain open.

## Reviewer credential registration intent trust boundary (#45, ADR 0021)

A compromised reviewer SQL login, API runtime or provisioner must not create a WebAuthn signing credential. V013 introduces a separate empty NOLOGIN registrar group (no seeded memberships), a migration-owner-approved immutable issuer/RP HTTPS origin allowlist, and a nonce-only registration intent with unique issuer/reviewer/RP binding, short expiry and no credential/active state. Function grants/table DML are explicitly restricted and tested against the old roles. **The supplied issuer, reviewer and registrar subjects are still plain caller strings; SQL issuance is not evidence that a real independent registrar authenticated or approved.** The schema owner can bypass ordinary append-only triggers. A future maintained FIDO2 verifier must check attestation, enrolled credential ID/COSE public key, current IdP role and independent registrar/first-reviewer consent *before* issuing any trusted signing grant, with atomic replay/revocation controls and independent WORM audit. On-prem/Azure production require HTTPS DNS, approved policy change record, locked migration credentials and guarded registration/recovery procedures. No direct WebAuthn assertion or SQL tenant approval grant was changed. See [ADR 0021](../adr/0021-registrar-only-unconsumable-credential-intent.md) and [registration runbook](WEBAUTHN_REGISTRAR_INTENT.md). #44, #38, #35/#31/#27, #17/#13 remain OPEN.

## Dual-principal registrar OIDC identity preflight (#47, ADR 0022)

A forged registrar claim, stale token role, disabled current Keycloak user, swapped JWT audience, weak ACR, replayed bearer, IdP outage or same-subject reviewer/registrar must **never establish independent WebAuthn credential trust**. The unconnected `ReviewerCredentialRegistrarIdentityGate` requires two distinct cryptographically verified JWTs with different pinned audiences and roles, a non-password-only exact ACR and fresh `auth_time` for BOTH subjects; fresh RFC7662 status and independent currently enabled account + effective realm role checks for BOTH, with fail-closed negative tests using real RS256 signed fixture tokens. Optional pending operator/admin exclusions must come from original privileged SQL scope; caller supplied strings alone are not evidence. A successful check is transient only, has NO nonce consumption or replay resistance, no Keycloak/DB atomicity, NO SQL grant or WebAuthn attestation. The V013 registrar group remains NOLOGIN with no members; any owner can still bypass ordinary append-only triggers. There is no live verified registrar service flow or independently held authenticator, no legal WORM/QTSP claim. #46/#44/#38 remain OPEN. See [ADR 0022](../adr/0022-registrar-dual-oidc-identity-preflight.md) and [operator guide](WEBAUTHN_REGISTRAR_IDENTITY.md).

## Disposable real browser registrar OTP/PKCE and live directory revocation test (#48; ADR 0023)

A signed OIDC bearer carrying `platform_credential_registrar` may be stale after current role removal or account disablement; a password-only enrollment screen does NOT prove successful second-factor authentication. The CI-only `temporalmark-mfa-ci` realm now has a **distinct** registrar and reviewer, each with fresh browser password+OTP login, separate PKCE public clients/audiences, signed `acr` + `auth_time`, live RFC7662 token introspection and independently queried current enabled account/effective realm roles. The registrar's role removal and account disablement are tested **after** valid JWT issuance, and the prior same signed bearer must be denied. A hardcoded disposable-loopback policy opt-in is not a production configuration or a generic HTTP exception. All test secret/token files remain ephemeral 0600 and browser tracing/screenshots/videos are disabled. No production independent human witness/device custody is proven; no WebAuthn credential, attestation or signed reviewer decision is introduced; V013 registrar role remains NOLOGIN with no seeded membership. #46 still needs approved registrar service issuance and production IAM; #44/#38 still need signed registration and decision with SQL privilege cutover. The fixture is NOT WORM or QTSP evidence (#17/#13). See [ADR 0023](../adr/0023-disposable-keycloak-registrar-browser-mfa.md) and [runbook](KEYCLOAK_REGISTRAR_MFA_CI.md).

## Registrar OIDC identity to SQL-intent bridge (ADR 0024, #49)

A validated two-person Keycloak OIDC assertion is a **snapshot**, and passing it to a SQL procedure is not cryptographic WebAuthn possession or independent human assent. The isolated registrar-only CLI requires two owner-protected token files, pinned HTTPS issuer/distinct audiences/fresh claimed MFA ACR/live RFC7662+currently enabled/effective roles, a CAB-approved exact reviewer subject and RP/origin, and a *separately configured dedicated registrar SQL login*. Npgsql explicitly verifies actual session_user=current_user, narrow NOLOGIN registrar-group membership, no superuser/CREATEROLE/CREATEDB and no table SELECT/DML rights before calling the V013 one-ever unconsumable intent function. No SQL login or group membership is seeded in migrations, and no API/PWA endpoint is exposed. **A stolen registrar SQL login can still invoke V013 directly, bypassing OIDC**; stolen migration-owner credentials can bypass the append-only triggers. A successful DB nonce cannot register a credential, approve a tenant or serve as WORM evidence; the registrar login must be independently approved, vaulted, network isolated, monitored, and accompanied by an audited one-time FIDO2 ceremony under #46/#44. Time-of-check/time-of-use remains between IdP checks and SQL commit. The direct historical unsigned approval/rejection SQL grants are untouched, requiring signature-gated cutover under #38. Legal qualification and WORM controls remain #13/#17. See [ADR 0024](../adr/0024-isolated-registrar-sql-intent-workflow.md) and [operator runbook](REGISTRAR_SQL_INTENT.md).

### Registrar SQL mixed-role privilege escalation denial

An independently configured registrar executor must never also be a member of approver, provisioner, or API runtime SQL groups. Live negative PostgreSQL tests GRANT each conflicting membership and require that the production Npgsql adapter fail closed before issuance. The adapter checks these memberships on the **actual opened connection**, in addition to session_user/current_user and absence of direct table privileges. No additional default role grant was created. A directly compromised legitimate narrow registrar LOGIN still bypasses the OIDC application gate; production requires the independently governed/vault-isolated service and signature-bound transaction from #46/#44.

## Forward-only V015 registrar direct-SQL bypass stop-line (ADR 0025; #51)

A stolen otherwise legitimate registrar SQL login could directly invoke V013's arbitrary-subject SECURITY DEFINER function, bypassing signed JWT and current Keycloak role checks in the standalone CLI. The resulting nonce was never a trusted WebAuthn credential, but would be unsafe to accept for future registration. V015 REVOKES the group's EXECUTE plus PUBLIC and legacy roles, so neither stolen nor honest registrar LOGIN can call the legacy function after migration. The original Npgsql adapter is hard-locked even on mistaken manual regrants; it cannot activate credentials or issue an unconsumable nonce. Tests use temporary dedicated SQL logins, verify direct SQL permission denial, no rows minted, fail-closed mixed-role privilege checks and lack of silent reenable via manual EXECUTE. Schema owners can still modify permissions and use the legacy function: no SQL privilege scheme removes DB-owner trust. **This is a deliberate feature freeze**, not signed release verification. A real registration must authenticate and check registered signing keys and consent, bind the exact nonce and actor scope, consume once in a transaction, and seal independent audit (#50/#44/#46); legacy unsigned approver SQL grants remain a different #38 blocker. No production registrar configured, no legal WORM/QTSP status (#17/#13). See [ADR 0025](../adr/0025-fail-closed-registrar-sql-issuance-interlock.md).

### V016 direct SQL regrant bypass denial (#51)

An owner can mistakenly grant `EXECUTE` directly to a registrar LOGIN even after V015 removed the NOLOGIN group's grant. The .NET store already fails closed, but the stolen SQL LOGIN could have called V013 directly and inserted an unsigned, unconsumable nonce. V016 adds a SECURITY DEFINER trigger that compares **original authenticated `session_user`** with the **trigger owner's `current_user`** and prevents any **nonowner INSERT**, including through V013 SECURITY DEFINER, returning insufficient privilege. A migration owner/superuser retains ordinary schema control and may bypass/disable triggers; owner rights are not signer evidence. No signed device, credential, attestation, transactional consumption or WORM/qualified timestamp capability is added. See [ADR 0025](../adr/0025-fail-closed-registrar-sql-issuance-interlock.md).

## Isolated Fido2 4.3.3 attestation candidate verification (#52; ADR 0026)

The previous WebAuthn preflight predicates were **not cryptographic**. A new infrastructure-only component now passes raw attestation responses and matching **original server-side** `CredentialCreateOptions` to the maintained stable Fido2 4.3.3 `MakeNewCredentialAsync` parser/verifier, after exact nonce/RP/origin/UV, attestation type and bound actor/handle checks. Invalid CBOR/JSON is rejected by a real-library regression. Untrusted user-provided credential ID, RP, unsigned UV flag, callback or synthetic unit-test success cannot be used for a key-registration decision. The result only contains SHA-256 digests/attestation metadata and the fixed **UNAPPROVED** status; no raw verified COSE key, credential registry, DB write, API path or registrar SQL grant is available. `none` and `self` attestation are denied, but `basic` format alone does NOT prove trusted supply-chain provenance without a reviewed metadata/certificate chain and human device custody. The global unique-ID callback is NOT yet backed by a real registry; an injected fake can only produce an unapproved candidate. V015/V016 still suspend direct SQL issuance; actual signed one-time registrar consent/credential activation and revocation are outstanding #44/#50/#46/#38. See [ADR 0026](../adr/0026-fido2-registration-candidate-verifier.md) and [candidate runbook](WEBAUTHN_ATTESTATION_CANDIDATE.md). No qualified WORM/QTSP status.


## Real `packed` signed-test fixture vs hardware provenance (#54, ADR 0027)

The isolated WebAuthn candidate verifier now has xUnit coverage using a genuinely signed test-only ECDSA P-256 `packed` attestation with an ephemeral private CA/leaf and a different credential public key, verified by **real Fido2 4.3.3**. Negative testing includes independently re-signed wrong RP/origin/challenge/UP/UV and signed-data/key/signature/certificate mutations, plus duplicate credential-ID refusal. The output is still only `UNAPPROVED` hashed metadata. This establishes a **cryptographic regression**, not authenticator origin assurance, real human key custody, independently accepted manufacturer certificate chain, FIDO certification or reviewer consent.

A compromised/randomly generated certificate can satisfy packed cryptography when metadata trust validation is absent. Production must independently pin and validate MDS signed BLOB and signer chain, freshness/serial rollback, authenticator status (including REVOKED and verification bypass), trusted AAGUID/attestation CA path, lifecycle/rotation and fail-closed MDS outages. Attestation hardware identifiers can be personal data; require a DPIA and limited retention. Test-only CA must never be added to production trust. The attacker-controlled global-uniqueness callback still has no SQL registry and a stolen privileged SQL identity remains a bypass to legacy reviewer decisions. V015/V016, the suspended registrar CLI, and all security parent issue blockers remain unchanged. No WORM or QTSP-qualified assurance is inferred.


## FIDO MDS signer-chain/revocation rollover threat and preflight (#56 / #55)

FIDO MDS changed its root from GlobalSign R3 to **R46** in August 2026; the added R3→R46 cross-certificate is transitional and expires on **2029-03-18**, together with R3. The pinned Fido2 4.3.3 upstream metadata repository still embeds R3 and has different revocation handling paths (one uses `X509RevocationMode.NoCheck` when constructing a system-trusted chain). An MDS BLOB verifying structurally under an old/hardcoded chain **must not** be equated with an independently approved signed BLOB, live nonrevoked signer, valid hardware attestation certificate, or enrolled key.

The #56 policy preflight uses **untrusted** Fido2 model objects (not signed input); it rejects dangerous statuses, malformed anchors, stale data, rollback, ambiguous AAGUID and anything but high-assurance proposed certification statuses. Even a successful result is `UNAPPROVED`, contains no keys and has no SQL/API caller. Attacker-controlled model data, spoofed observation times or minimum serials, unsigned CA fields, false certification and certificate revocation remain **threats** until #55 implements independently pinned signed-JWS/x5c verification, RFC5280 CRLs/OCSP and known FIDO root migration, trusted immutable monotonic snapshot, model-specific attestation chain, fail-closed outage/air-gap policy and DPIA. V015/V016 and suspended registrar CLI stay frozen; parent #44/#50/#46/#38 remain release blockers. See [ADR 0028](../adr/0028-fail-closed-non-authorizing-mds-metadata-policy.md) and [MDS runbook](WEBAUTHN_MDS_POLICY.md).


## Real JWS test-signature proof is not revocation or MDS signer trust (#58/#57)

An isolated xUnit fixture now issues genuine RS256/JWS tokens with ephemeral test-only X.509 root and signer keys; TemporalMark's detached crypto preflight calls the maintained Microsoft.IdentityModel JWS verifier and pins an explicit root using `X509ChainTrustMode.CustomRootTrust`. It denies malformed/forged JWS, signer/root swaps, injected `x5c`, expired leafs, caller-selected `x5u`/JWK URLs and forged serial/freshness headers. **Security limit:** it explicitly sets `RevocationMode.NoCheck` for an isolated non-authorizing chain demonstration; a revoked signer may still pass this preflight, so the response is permanently `UNAPPROVED`, with no signer or credential data. Never treat this as CAB-approved certificate revocation or FIDO MDS authenticated provenance; the caller-selected root is not a production trust anchor. FIDO's Aug 2026 R46 change and transitional R3 x5c chain (expiry 2029-03-18) remain a production compatibility/rotation risk.

A complete protection must fail closed on signed CRL/OCSP expiry/outage, unrelated public CA trust, unknown/cross-signed root, untrusted certificate URL SSRF, signed metadata rollback after restart, stale device-status reports and separate attestation root/firmware compromise. Until #57/#55 and independent approval are delivered, no WebAuthn credential enrollment, SQL signer grant, tenant decision, WORM or QTSP claim. See [ADR 0029](../adr/0029-isolated-mds-jws-chain-candidate-without-revocation-trust.md) and [runbook](WEBAUTHN_MDS_JWS_PRECHECK.md).


## Signed offline CRL *test* does not establish FIDO signer trust (#59 / #57)

An isolated BouncyCastle 2.7.0 X509 v2 DER CRL verifier tests a real CA signature and revoked serial against a single directly issued leaf. Fail-closed cases cover forged issuer/signature, missing/invalid/expired CRLs, unsupported critical/delta/indirect extensions, missing cRLSign, unbounded CRL bytes and wrong certificate validity. The issuer CA is **caller-selected**, and the .NET `CustomRootTrust` path is used only to verify the test certificate was directly issued by that CA; the code's status is always `UNAPPROVED/CRL_SIGNATURE_CHECK_ONLY_ROOT_UNTRUSTED` and it has no registration/SQL caller. **Threats still unmitigated:** a malicious CA can sign a valid-looking CRL, required intermediate/root revocations are not checked, a stale same-version CRL can be replayed, no authenticated CRL distribution/issuer ID binding or independent trusted time exists, and there is no live FIDO R46 root chain or immutable signer/status checkpoint. FIDO's R3→R46 2026 migration and 2029-03-18 transition deadline remain #57. Deployment owners must not upgrade this preflight to production authorization; all on-prem/Azure paths need fail-closed rooted and audited CRL/OCSP validation and independent attestation/MFA/consent controls. No WORM or QTSP claim. See [ADR 0030](../adr/0030-offline-direct-issuer-crl-cryptographic-preflight.md) and [runbook](WEBAUTHN_MDS_OFFLINE_CRL.md).


## Two-hop offline CRL security boundary (#60)

The isolated ADR 0031 regression checks a **test-only** signer leaf + intermediate CA + root path, requiring a separate correctly signed, current DER v2 CRL for **each non-root certificate**, including the intermediate itself. It shares the BouncyCastle v2 CRL parser/signature/serial algorithm with ADR 0030; a direct signer with a clean CRL is still **rejected** when the intermediate has a signed revocation. Host trust, AIA/issuer URL downloads, missing CRL, wrong issuer or swapped/hijacked path fail closed. The certificate-signature chain is constructed with `CustomRootTrust` and `RevocationMode.NoCheck` **only** for path cryptography; explicit CRL checks are mandatory afterwards.

The root is entirely **caller-selected**. Consequently this only tests revocation cryptography, not authenticity of the **real** FIDO R46 signing root, full 2026 cross-cert path, reliable CRL source, issuer AKI/CDP and delegate scope, status beyond local snapshots, trusted time, CRLNumber/serial antirollback or multi-region/offline update safety. A forged CA+CRL may still produce an `UNAPPROVED` observation: no trusted/active identity or SQL function accepts it. Do not wire it to a registered credential, trusted FIDO MDS metadata, tenant approval or timestamp issuance until #57/#55/#53 and CAB/DPIA controls are independently complete. #44/#50/#46/#38 and V015/V016 remain frozen. See [ADR 0031](../adr/0031-two-hop-offline-mds-crl-with-untrusted-root.md) and [runbook](WEBAUTHN_MDS_TWO_HOP_CRL.md).


## V017 local UNAPPROVED checkpoint does not stop trusted snapshot rollback (#62 / #61)

The newly introduced owner-only PostgreSQL V017 diagnostic checkpoint stores a claimed issuer-key SHA256, content digest, strictly increasing version and local validity/append-only-by-trigger history for `MDS_BLOB` or `ISSUER_CRL`. It rejects same-version different content and a lower version **within the same database primary** and tests competing connections under PostgreSQL row locking. No untrusted runtime, approver, provisioner or registrar SQL group has INSERT/EXECUTE/SELECT authority on this schema; the only returned status is `UNAPPROVED`. All source-policy SHA256, evidence bytes and purported versions are **caller-asserted**, never verified against the actual FIDO Alliance R46 signing root or authenticated CRLs.

**Unmitigated high-severity threats:** restoring a pre-checkpoint backup erases the highest signed version; malicious schema owners/superusers can modify normal tables or disable triggers; replica split-brain can produce independent valid-looking serial lines; system clock rollback, compromised import root, unsigned/incorrect issuer AKI/CDP, truncated audit history, revoked/expired manufacturer signer or forged chain can yield untrusted inputs. V017 alone neither validates those inputs nor supplies independent immutable version witness, signed off-host audit, trusted time, CRL/OCSP transport, CAB approval or attestation metadata status. The database candidate should NEVER be promoted into a trusted registry, WebAuthn key activation, SQL authorization or credential grant. Parent #61 and #57/#55/#53/#44/#50/#46/#38 remain release-blocking. See [ADR 0032](../adr/0032-owner-only-unapproved-mds-crl-checkpoint-staging.md) and [runbook](MDS_CRL_UNAPPROVED_CHECKPOINT.md).

## Signed checkpoint witness may be replayed with old DB backup (#63 / #61)

An isolated offline test `ReviewerMdsOfflineSignedCheckpointWitnessReconciler` verifies RSA-PSS SHA256 over **original canonical domain-separated manifest bytes** and reconciles an exactly scoped V017 set of untrusted `MDS_BLOB`/`ISSUER_CRL` candidate versions/digests under PostgreSQL `REPEATABLE READ READ ONLY`. It detects a restored lower version, same-version content equivocation, missing/extra/newer rows and denied unprivileged reads **only if the caller supplies the authentic latest witness and accepted test key**. Expired/unknown signed witness, unrecognized root, duplicate/unsorted records and malformed observations fail closed. Output remains **UNAPPROVED**, and no code consumes it to activate any identity or grant SQL access.

**Unmitigated critical replay risk:** the RSA test verification key is entirely **caller selected**; attacker can sign a new manifest. A privileged owner can restore an old DB backup **together with an old once-valid signed witness**; no separately trusted monotonic external high-water-mark, HSM custody, root rotation, witness issuance attestation, immutable audit, independent clock or real full backup/restore exercise exists. A read-only database snapshot also does not lock a future issuance decision; absence of a trusted witness store means TOCTOU and multi-primary replay are unresolved. No official FIDO R46 source, signed CRLNumber/AKI/CDP or live authenticator-status validation is connected. **#61/#57/#55/#53/#44/#50/#46/#38** remain OPEN, V015/V016 and registrar CLI blocked; no WORM, eIDAS or QTSP claims. See [ADR 0033](../adr/0033-non-authorizing-external-signed-checkpoint-witness-reconciliation.md) and [runbook](MDS_CRL_SIGNED_WITNESS_RECONCILIATION.md).

## Two separately signed test witnesses still rely on external **latest seal** custody (#65)

ADR 0034's offline candidate verifies an RSA-PSS signed manifest and a **separately** RSA-PSS signed high-water seal, pins the test seal authority's SPKI digest and the signed **latest seal bytes digest**, checks canonical source scope and time, then reconciles the original witness through a read-only repeatable-read V017 checkpoint query. Live PostgreSQL `COPY TO STDOUT / COPY FROM STDIN` tests restore old rows after a newer signed version has been observed while retaining the latest test seal SHA **outside the database**; restored-lower serial and old signed witness+seal fail under the retained newer pin. Both signatures and pins are **caller supplied**, and results always `UNAPPROVED`; no credential authority or FIDO signer trust.

**Critical residual attack demonstrably possible:** a malicious operator who can replace the `independentlyExpectedLatestSealSha256` input together with an old database and previously valid old seal can still obtain an `UNAPPROVED` observation. This is neither an immutable latest seal nor independent trust. The test COPY rollback is **not** full `pg_dump/pg_restore`, recovery across regions or independently audited immutable storage. Missing or hostile seal key bootstrap, source policy, signed CRLNumber/issuer provenance, trusted time, signer rotation, replication fork and compromise of owner remain #64/#61/#57/#55. No app/API/CLI wiring, new SQL role, WORM or qualified timestamp claims. See [ADR 0034](../adr/0034-test-only-sealed-high-water-witness-and-scoped-copy-restore.md) and [runbook](MDS_CRL_SEALED_HIGH_WATER_COPY_RESTORE.md).

## Full PostgreSQL logical restore is insufficient for independent high-water custody (#66)

CI now exercises `pg_dump -Fc` of the **complete** PostgreSQL test database and `pg_restore --single-transaction --no-owner` of the old archive into a **separate** database on the same PostgreSQL 17 instance, preserving SQL grants/revokes and 17 versioned migrations. The live original is advanced from a synthetic V017 serial 3 to serial 4 before restoring serial 3. Two disposable RSA-PSS test signers and a latest-seal digest kept **in test-process memory outside both DBs** demonstrate rejection of restored-lower checkpoint with newest manifest, rejection of earlier valid signed seal with newer retained pin, and digest equivocation; a simultaneous replacement of the 'latest' pin with an older value exposes the attack that still passes the conditional `UNAPPROVED` inspection. No application authority or FIDO trust is emitted.

Critical **unmitigated** threats: the test seal signer public key and latest-seal digest are caller-selected, not pinned by an independent root or immutable witness; malicious DB and witness operators may replay old DB + old signatures + old pin; the test restores to a different DB in the **same server** without verifying physical backup/WAL/PITR, independent cluster, cross-region state, data-loss/RPO, object store immutability, real production secrets or a secure recovery runbook. A backup restored with `--no-acl` could silently lose SQL revoke protections; the regression explicitly **retains ACL** and tests the restored role boundaries. Production evidence custody, FIDO R46 signed source, CRL/OCSP, CAB/DPIA and hardware enrollment remain blockers #64/#61/#57/#55/#53/#44/#50/#46/#38. V015/V016 remain frozen. See [ADR 0035](../adr/0035-test-only-full-logical-pg-dump-restore-vs-signed-seal.md) and [runbook](MDS_CRL_FULL_PGDUMP_RESTORE_TEST.md).

## Local signed file journal can be rolled back with its whole host backup (#67)

ADR 0036 introduces an independent *file location* for the test-only MDS/CRL latest-seal SHA, outside the V017 PostgreSQL database. It uses bounded canonical signed RSA-PSS/SHA256 events, a monotonic serial and a SHA256 previous-entry hash, exclusive per-file open, fully verified append/reopen and OS flush. A corrupted/empty/missing file, wrong source/signing-key pin, bad signature, stale/retrograde timestamp, duplicate/older serial or partial write fail closed. The real full logical `pg_dump/pg_restore` CI regression reads this separate signed journal after restoring a lower DB checkpoint and denies an older signed witness against the journal's latest digest.

**Critical limitation:** the journal is an **ordinary mutable file**, and its test RSA key and pin can be controlled by the same CI operator/host administrator. Restoring an older VALID journal along with the old database (or replacing the pinned key) can reproduce a matching old state despite valid signatures and a hash chain. `FileShare.None` is not a sandbox, symlink hardening, network-wide lock, approved HSM or WORM guarantee. `Flush(true)` does not make durable cross-cluster monotonic evidence, and reading the file before SQL reconciliation has a TOCTOU gap. File loss and corrupted partial append require independent reviewed recovery, not auto-bootstrap. #64/#61 remain OPEN for independent immutable witness custody, signer trust root, key rotation, region DR and human governance. The journal never upgrades FIDO R46 signer/CRL provenance or WebAuthn enrollment, SQL V015/V016 blocks stay intact; no eIDAS/QTSP/WORM claim. See [ADR 0036](../adr/0036-fail-closed-test-signed-file-high-water-journal.md) and [runbook](MDS_CRL_SIGNED_FILE_HIGH_WATER_JOURNAL.md).

## Offline file journal: preexisting symlink and reparse redirection (#68)

The test-only RSA-PSS signed MDS/CRL high-water file journal previously followed a path that could be a symlink to an authentic signed journal or traverse a symlinked ancestor directory. ADR 0037 introduces explicit checks of **all present ancestor directories and final file path** using .NET 10 link target and reparse-point indicators before and after opening, including fail-closed dangling links; Linux xUnit checks that attempts through links cannot inspect or append and do not alter the authentic target. Existing signed hash-chain, bounds and monotonic serial checks remain intact, with output only `UNAPPROVED`.

**Risk remains critically open:** checking filesystem paths is NOT atomic secure handle acquisition. A privileged host administrator can switch a symlink, rename a parent, create a hardlink/bind mount, replace the genuine journal with an earlier signed file or replace the test public-key pin before/after these checks. Directory ownership, handle-relative `openat2/O_NOFOLLOW`, mount constraints, independent signed immutable high-water authority and cross-region/PITR/custody are not implemented. Parent #64/#61/#57/#55/#53/#44/#50/#46/#38 remain OPEN; V015/V016 freeze, FIDO R46 signed source governance and credential activation remain blocked. See [ADR 0037](../adr/0037-best-effort-symlink-reparse-test-journal-path-denial.md).

## Isolated CI witness PostgreSQL is a second server, NOT independent immutable custody (#69)

ADR 0038 introduces a **second `postgres:17.6-alpine` server** under an opt-in Docker **`witness-ci`** test profile with its **own volume and role database**; the standard application stack/API has no mandatory dependency on it. The test-only owner SQL function uses PostgreSQL atomic `INSERT ON CONFLICT DO UPDATE ... WHERE higher_serial`, appends an event in the same transaction, and denies equal/older/different-digest reuse. A different witness **reader** role can SELECT the latest synthetic seal SHA but has **no write, truncate, audit-table read or writer EXECUTE**. Real CI `pg_dump -Fc / pg_restore` of the **entire original main DB** demonstrably does not roll back the separate witness server; `pg_control_system().system_identifier` confirms independent PostgreSQL clusters. The new .NET preflight enforces that role contract under READ ONLY REPEATABLE READ, then reuses original signed-manifest/seal verification to reject restored lower versions. All positive results remain `UNAPPROVED`; absence, stale/future observation, wrong signature or root pin and witness outage deny.

**Unmitigated critical threats:** both PostgreSQL containers/volumes and disposable signer keys remain controlled by the SAME CI Docker host and owner. A host/root operator can restore BOTH databases or rewrite the witness rows/events as its superuser, replace caller-selected test public keys, or race the two independent read-only snapshots. This is **not** CAB/HSM/governed WORM custody, immutable latest-version authority, offsite physical cluster/PITR/region failover, production on-prem/Azure parity or authentic signed FIDO R46 JWS/CRL issuer provenance. A second DB offers narrower operator-role separation **only inside the synthetic CI scope**, not production security qualification. Parent #64/#61/#57/#55/#53/#44/#50/#46/#38 remain OPEN, V015/V016 issuance and registrar CLI frozen; no active WebAuthn/eIDAS/QTSP claims. See [ADR 0038](../adr/0038-ci-only-separate-postgresql-witness-instance.md) and [runbook](MDS_CRL_SEPARATE_POSTGRES_WITNESS_TEST.md).

## Witness-server EXECUTE-only writer narrows SQL compromise, NOT administrative rollback (#70)

ADR 0039 separates the **CI-only second PostgreSQL witness** into a NOLOGIN/NOSUPERUSER data owner for checkpoint/audit tables and a restricted SECURITY DEFINER atomic append function; the only writer login is NOSUPERUSER with **EXECUTE on that function only**, no direct table/audit/identity-sequence read/write/truncate, database TEMP, public schema CREATE or membership of data owner. The independent existing reader has SELECT on current synthetic checkpoint ONLY and no function EXECUTE. PostgreSQL's default PUBLIC EXECUTE and DB TEMP grants must be revoked **in the same bootstrap transaction** as function creation, with fixed `search_path=pg_catalog,pg_temp`, fully qualified `public` SQL and no dynamic SQL. Live xUnit fails closed on direct writer mutation, even after full main PostgreSQL logical restore. The output remains UNAPPROVED.

**Open high-severity attacks:** this does not constrain the witness PostgreSQL superuser or Docker host root that controls both volumes, server and test credentials. The superuser may rewrite tables, spoof audit, alter function, impersonate roles, roll back both DBs, or replace synthetic signing keys. The EXECUTE-only writer still submits attacker-chosen serials/digests because actual FIDO R46 root/JWS/CRL status or independent CAB/HSM signing authority is not implemented. Multi-cluster atomic snapshots, separation of the actual hosting administrators, high-water monotonic offsite immutable log, safe rotation/recovery, PITR/region DR, audit and eIDAS/WORM/QTSP status remain #64/#61/#57/#55/#53/#44/#50/#46/#38 blockers. V015/V016 SQL freeze and registrar CLI remain suspended. See [ADR 0039](../adr/0039-ci-nonlogin-definer-and-execute-only-witness-writer.md), [runbook](MDS_CRL_EXECUTE_ONLY_WITNESS_WRITER_TEST.md).

## Mandatory restore CI test filter regression corrected (#69/#70)

The former `mds-full-pgdump-restore.sh` used a filter naming only `MdsFullPgDumpRestorePostgresTests` and did **not** execute the separate-cluster `MdsSeparatePostgresWitnessRestoreTests`, although it launched the second PostgreSQL server and checked its bootstrap. The issue #69 was reopened after discovery; previous reports of successful second-server xUnit execution were premature. The filter now expressly includes **BOTH** suites. A real RED run executed 2 tests and failed 1 because the restricted writer login had not yet been provisioned, proving selection. The GREEN fixture serializes shared restored-DB tests and restores a deliberately mutated old digest before subsequent tests. This CI-coverage regression illustrates why binary green status is not sufficient without checking the **actual tests selected and executed**; it does not alter any V017 application SQL or production authority.

## Workbox navigation fallback confusion (#71, ADR 0040)

A browser-controlled PWA service worker can answer an HTML-oriented navigation to `/api/...` with the precached SPA shell if `navigateFallback` is not restricted; a real production-build Playwright RED test observed HTTP 200 for a backend 404 (CI 43842598997). This hides the backend's actual response and may confuse clients or operators; the finding does **not** imply API data was persisted in CacheStorage. The patched worker excludes `/api`, `/healthz` and `/realms` navigation paths via anchored Workbox `navigateFallbackDenylist` and retains `runtimeCaching: []`; production-worker Chromium tests require a controlling worker and check backend 404 and no cached API URLs. This client-side routing policy is not a tenant authorization boundary: the API must still enforce authenticated, tenant-scoped access, secure response headers and no-cache on sensitive exports. Stale or hostile workers, browser HTTP cache, CSP/XSS and offline recovery remain unresolved in parent #20. [Runbook](PWA_SERVICE_WORKER_SECURITY.md).

## Two-database coordinated rollback and ordinary signed-file tripwire (#72, ADR 0041)

Existing PostgreSQL 17 primary restore and independent CI PostgreSQL witness (ADR 0038/0039) do not prevent a **witness superuser** from restoring its checkpoint to the same older signed serial as the primary database backup: two-source preflight accepts the consistent old+old candidate as only `UNAPPROVED`. The new non-authorizing three-source composition (ADR 0041) also checks a separately retained, caller-test-key signed local file journal. It denies if that journal retains the latest serial 4 while both SQL databases claim 3; it verifies original signed bytes and hashes via existing components and performs a final journal re-read. It also denies missing/corrupt/mismatched file and caller-selected test pin. However a CI host/backup operator can replay **ALL THREE** stores to serial 3 while preserving cryptographically valid old signatures; the three-store verifier would still return `UNAPPROVED`. Multiple mutable copies, even independently signed, are NOT externally anchored monotonic truth. No global atomicity, CAB/HSM provenance, independent signer/immutability/offsite admin separation, full physical PITR/region split brain or actual FIDO root/CRL governance. Never activate production credential or eIDAS qualified evidence on this basis. See [runbook](MDS_CRL_THREE_SOURCE_ROLLBACK_TEST.md); keep #64/#61/#57/#55/#53/#44/#50/#46/#38 open.

## Internal witness checkpoint vs append-event equivocation (#73, ADR 0042)

Before #73, a witness superuser could downgrade only the separate PostgreSQL latest checkpoint or mutate an audit event while the two-source reader ignored all append history. A correctly signed restored primary with matching synthetic latest row could be accepted as merely UNAPPROVED despite an audit event proving a newer or different signed-seal digest. The CI-only `STABLE SECURITY DEFINER` read-only, bounded audit checker now runs under the same REPEATABLE READ snapshot with reader-only EXECUTE, no direct audit SELECT, fixed search path and strict function ACL/owner checks. It compares **all retained source-scoped events**, chronological serial progression and latest SHA with the checkpoint; a mismatched or missing tail denies. But a privileged witness superuser can rewrite the entire history too, and an app/Docker/backup host can replay the ordinary signed journal and old primary snapshot together: neither SQL audit nor this three-store test provides externally anchored monotonic truth, immutable history, independent operator control or legal evidentiary trust. This remains #64/#61 and #57 root/CRL and CAB/HSM production blockers. See [ADR 0042](../adr/0042-ci-witness-bounded-audit-history-reconciliation.md) and [runbook](MDS_CRL_WITNESS_AUDIT_RECONCILIATION.md).

## Mutable CI action sources (#74, ADR 0043)

Version-alias GitHub Actions references in the original workflow allowed a rerun on the same TemporalMark SHA to load different external action code as tags moved. An offline Python source policy now rejects unpinned external uses, including branch/tag names, short SHAs and local path traversal, with full unit tests. Real RED run 43857785628 demonstrated ten rejected aliases; every instance is now pinned to a full action commit SHA verified against public GitHub tag refs. This narrows unreviewed CI source drift, but pinning does NOT prove the pinned code is safe, stop mutable transitive downloads or replace code review, branch protection, signed release attestations or a trusted builder. npm lockfiles, container image digests, security scanners and CAB artifact evidence still belong to parent #20. It does not make the witness trust architecture (#64/#61) independent or qualify FIDO/eIDAS services. See ADR 0043 and docs/CI_ACTION_PINNING.md.

## npm transitive dependency drift / integrity in PWA and test runner (#75, ADR 0044)

Before #75, both Node projects had exact top-level package versions but no committed dependency closure; CI and Docker ran npm install, so a fixed source commit could resolve new transitive versions and tarballs on subsequent runs. The two genuine npm v10 lockfileVersion 3 artifacts now specify each resolved package version, HTTPS registry URL and integrity; npm ci is mandatory for the PWA, Playwright test runner and Docker frontend build. Offline Python source guards require both manifests and lockfiles to match, verify the registry package tree and prevent npm install from reappearing in CI or Docker. RED [CI 43861421062](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43861421062) demonstrated missing lockfiles and mutable install rejection after five unit tests passed. This is dependency resolution/integrity, NOT a guarantee of safe packages, sandboxed scripts, immutable transitive network resources, signed SBOM/attestations or a genuinely reproducible binary. Image digest, GitHub runner provenance, SAST/SCA/SBOM and CAB review remain #20; independent trustworthy witness #64/#61 and FIDO metadata #57 remain release blockers. See [runbook](NPM_LOCKED_INSTALLS.md).

## Mutable container image tag substitution (#76, ADR 0045)

GitHub Action source commits and npm tarball integrity locks did not stop dynamic substitution of PostgreSQL, Keycloak, SDK, runtime, Node or Nginx container images on a fixed TemporalMark commit: prior Compose and Dockerfiles had eight floating image references. The test-first offline policy checks every application Dockerfile FROM and test Compose image declaration for an explicit complete lowercase OCI `sha256` digest, with no tag-only fallback. Real [RED CI 43868733873](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43868733873) passed five policy tests and rejected all eight source occurrences; six registry manifest/index SHA256 values were independently observed in [CI 43869063858](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43869063858), then fixed as tag@digest. This pins **image manifest selection**, not publisher authorization, signature trust, vulnerability-free OS packages, runtime dynamic dependency downloads or identical multi-platform behavior. Compromised builder/registry/runner and unavailable manifests remain risks. No production HSM/WORM, independent witness, certified on-prem/Azure equivalence, FIDO R46 chain or QTSP/eIDAS status is delivered. Parent #20, #64/#61/#57 and evidence #17 remain open; V015/V016 issuance freeze unchanged. See [ADR 0045](../adr/0045-registry-image-digest-pins-ci.md) and [runbook](CI_DOCKER_IMAGE_DIGESTS.md).

## CI npm lockfile inventory visibility vs complete software provenance (#77, ADR 0046)

Two npm 10 v3 lockfiles pinned by #75 identify the source dependency closure but did not produce separately inspectable supply-chain inventory artifacts. A Python-stdlib CycloneDX JSON 1.5 converter now lists every lockfile npm registry component with unique path-qualified references, scoped npm purl, hash decoded from the original SRI, exact source-lock SHA256 and dev/optional properties. The generated PWA and Playwright artifacts have 474 and 8 component occurrences respectively and are verified against original lockfiles before upload by SHA-pinned GitHub Actions, with **7-day** retention. A test-first [RED CI 43873432766](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43873432766) demonstrated absent evidence; [GREEN CI 43874005747](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43874005747) uploaded the inventory. Important: an npm lockfile can include optional binaries not actually installed and misses non-npm packages, downloaded browser binaries, OS, .NET and container contents. SRI is not a trusted publisher signature, schema-inventory consistency is not vulnerability analysis, and GitHub artifacts are NOT signed/WORM/long-term legal evidence. Independently verified whole-product SBOM and SAST/SCA/attestation/registry publisher verification remain #20; independent witness #64/#61 and FIDO trust #57 remain release blockers. See [ADR 0046](../adr/0046-ci-npm-lockfile-cyclonedx-inventory.md) and [runbook](CI_NPM_CYCLONEDX_SBOM.md).

## NuGet restored-dependency inventory vs signed/complete software SBOM (#78, ADR 0047)

Prior CI had a two-project npm SBOM but no independently inspectable .NET NuGet dependency inventory for the nine production/test projects. .NET 10 SDK `dotnet restore` produces temporary project-specific `obj/project.assets.json` (SDK schema v3 or v4) with package IDs, resolved versions, and NuGet SHA-512 metadata. CI now explicitly restores all nine projects, parses only `type: package` entries with canonical SHA-512, creates per-project unique `pkg:nuget` CycloneDX 1.5 components, embeds exact project/asset SHA-256 metadata, verifies the inventory against current restored sources and uploads only JSON with seven-day retention. Real source-policy RED [43877379110](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43877379110) caught absent NuGet evidence; [CI 43878993393](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43878993393) generated and verified **185** package occurrences and artifact ID 14231163433. **NuGet project.assets.json is not a stable public API and is not a committed NuGet dependency lockfile** (v4 SDK compatibility explicitly tested); a future unreviewed change or feed may alter resolved contents. Metadata SHA-512 is not a package publisher identity signature, CI artifact is not signed or WORM, and this inventory does NOT cover installed binaries, container OS images, Azure on-prem distribution, native libraries, secrets, vulnerabilities or end-to-end supply chain. Lock-mode NuGet, complete OCI SBOM, vulnerability scanning, SAST/SCA and signed CAB release attestation remain #20, with independently governed witness #64 and authentic FIDO MDS root #57 still blocking security release. See [ADR 0047](../adr/0047-ci-nuget-restored-graph-cyclonedx-inventory.md) and [NuGet runbook](CI_NUGET_CYCLONEDX_SBOM.md).

## Mobile PWA identity and offline routing (#80, ADR 0048)

The Vite PWA previously omitted an explicit manifest `id`, so app identity was derived from `start_url`. A future homepage change could unintentionally create a distinct installed app; use stable same-origin root `id: "/"` independent of tenant or person. CI's Android-Chromium-emulated production-build test (not a physical-device installation) verifies delivered manifest, real PNG dimensions, controlling Workbox, offline static shell navigation, and that excluded `/api/` offline navigation cannot turn into successful cached HTML. All CacheStorage buckets must omit `/api`, `/realms`, `/healthz`. Test-first RED on [CI 43882463108](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43882463108) precisely demonstrated missing identity. See [ADR 0048](../adr/0048-stable-pwa-identity-mobile-offline-installability.md) and [mobile runbook](PWA_MOBILE_INSTALLABILITY_CI.md).

**Residual risk:** manifest declaration and Chromium emulation do not prove safe maskable artwork crop, native Android/iOS installation/launch, offline authentication, secure browser disk/HTTP caches, correct API cache headers, XSS/CSP/worker integrity, mobile device lifecycle or server-side tenant authorization. Do not store sensitive auth, marks or exports in an offline worker. No relation to V015/V016 SQL release interlocks, FIDO MDS trust, WORM or legal qualification; parent #20 and independent security blockers stay OPEN.

## NuGet graph drift and fail-closed build provenance (#79, ADR 0049)

Before this slice a fixed Git SHA could resolve different transitive packages because nine .NET projects had no committed NuGet lockfiles. Real SDK-produced lockfiles now bind the resolution and CI, Docker API and integration test paths require `--locked-mode` / `RestoreLockedMode=true`, with no-restore for backend build reuse. A source-level SHA-512 hash does not attest publisher, supply-chain safety or compiled artifact identity; SDK patches, unpinned tool downloads and feed availability remain distinct threats. See [ADR 0049](../adr/0049-nuget-locked-restoration-ci-docker.md) and [runbook](CI_NUGET_LOCKED_RESTORES.md). Reviewer/registrar V015/V016 freeze, MDS trust, WORM custody and legal qualification are unchanged.

## Deprecated Node20 action runtime fallback (#81, ADR 0050)

Pinning a GitHub Action by SHA protects source selection but not the executor's Node runtime. Successful [CI 43885569528](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43885569528) emitted Node20 deprecation warnings: GitHub silently forced several pinned Node20 actions to Node24. This cross-runtime execution is not reproducible by the source commit alone. [ADR 0050](../adr/0050-native-node24-sha-pinned-github-actions.md) pins five upstream-verified action revisions that **declare native Node24** and an independent fail-closed offline full-SHA runtime allowlist complements ADR 0043. A pinned action can still fetch mutable transitive code; production runner images, signatures, SCA, SAST, malicious dependencies and release attestation remain separate #20 risk. Reviewer SQL V015/V016, FIDO/CRL trust, WORM and eIDAS remain unchanged.

## Signed Keycloak HTTP two-tenant test matrix (#82, ADR 0051)

Existing pilot authenticated browser smoke had only one tenant, so it could not directly demonstrate HTTP 401/403 differentiation, cross-tenant TSR download denial or ZIP/audit scoping under independently signed users. CI now seeds only its **disposable** development realm with independent A/B principals and PostgreSQL synthetic Unverified canaries, invokes actual compiled API under real signed Keycloak JWTs, and checks returned evidence and prepared access audit without exposing tokens or using database owner access in the application. It rejects caller-provided org header/query/body selectors, wrong audience/issuer, expired bearer, missing scope or inactive SQL membership. Signed short-lived bearer expiration requires explicit zero `ClockSkew` rather than IdentityModel's implicit five-minute grace: this imposes a synchronized-clock availability requirement and is **not** a qualified clock or certified timestamp source. Owner-only canary seeding and the CI-only direct password grant do not prove production enrollment authorization, DB RLS or revocation, independent FIDO trust, certified WORM/legal eIDAS value or human WebAuthn review. See [ADR 0051](../adr/0051-ci-real-api-cross-tenant-keycloak-postgres-isolation.md) and [runbook](CI_API_TENANT_HTTP_ISOLATION.md). Parent #20/#14 and all security release blockers remain OPEN.

## External RFC 3161 TSA redirect/egress boundary (#83; ADR 0052)

The configured TSA URL is server-owned, but the default .NET `HttpClientHandler` follows HTTPS redirects, potentially forwarding a nonce/imprint-bearing RFC 3161 POST to an attacker-chosen second HTTPS host (especially HTTP 307/308). The `external-tsa` named client's dedicated primary handler now disables **all** automatic redirects and cookies; 301/302/303/307/308 fail closed before token parsing or storage. Both on-prem and Azure configurations still require separately reviewed DNS/IP, proxy and network egress restrictions and approved TSA host inventory. This transport hardening neither provides complete SSRF resistance nor qualified QTSP chain, revocation, EU Trusted List, WORM, HSM or legal evidence validation. See [ADR 0052](../adr/0052-external-tsa-http-no-redirect-policy.md), [operator guidance](TSA_HTTP_TRANSPORT.md), #15/#17/#13.

## RFC 3161 HTTP status/MIME ambiguity (#84; ADR 0053)

The external TSA endpoint could return HTTP 201/202/204/206, an HTML/JSON error page with HTTP 200, no Content-Type, or the mistyped `application/timestamp-response` from the uncorrected RFC 3161 text. Previously `IsSuccessStatusCode` accepted any 2xx and opened the DER stream before rejecting these responses; a misbehaving intermediary could waste bounded parser resources or ambiguously classify an upstream partial/polling response. The provider now requires exactly `200 OK` (a **strict local policy**) and a Content-Type media type exactly `application/timestamp-reply` per RFC 3161 §3.4 and verified erratum 1879, before reading any body. Wrong envelopes fail without logging upstream bytes or persisting a record. Header equality is untrusted metadata, **not** signature/certificate validation or proof of a qualified timestamp. The existing 1 MiB, timeout, no-redirect/no-cookie and tenant-owned configuration boundaries still apply. See [ADR 0053](../adr/0053-rfc3161-strict-http-response-envelope.md), [operator runbook](TSA_HTTP_TRANSPORT.md) and open parent #15. Network egress, full PKI/revocation/Trusted List, WORM and qualified issuance remain release blockers.

## External TSA endpoint URI authority — runtime bypass and static preflight (#85, ADR 0054)

The API previously limited **HTTP loopback** to development but the reusable `ExternalRfc3161TimestampProvider` silently allowed it independently; a server configuration error or alternate caller could send imprints to local services. The provider now checks endpoints on **every** call before HTTP send: non-HTTPS URLs, URI userinfo/fragment, HTTPS localhost, and IPv4/IPv6 literals are denied by default. Only an explicit `IHostEnvironment.IsDevelopment()` value injected by API DI authorizes HTTP(S) loopback for disposable tests. A tenant cannot choose or modify this setting; ordinary HTTPS DNS TSA URLs remain permitted. This is only static URI/host-name validation. **DNS rebinding, internal IP DNS answers, proxy override, link-local/metadata destinations via DNS and untrusted system resolver** still require audited connection-time egress restrictions and destination allowlist for both on-prem and Azure. No change to signature trust, qualified-status evidence, WORM, long-term custody, or timestamp `Unverified` state. See [ADR 0054](../adr/0054-rfc3161-endpoint-uri-development-loopback.md), [runbook](TSA_HTTP_TRANSPORT.md), #85 and open parent #15.

## Ambient OS/environment HTTP forward proxy bypass for external TSA (#86; ADR 0055)

The dedicated named `external-tsa` handler had `AllowAutoRedirect=false` and `UseCookies=false` but inherited `HttpClientHandler.UseProxy=true`. Runtime OS proxy or environment `HTTPS_PROXY`/`ALL_PROXY` could route an RFC3161 imprint/nonce-bearing request through an unreviewed intermediary despite server-owned URI preflight (#85). The handler now explicitly sets **`UseProxy=false`**, maintaining one direct egress path for this pilot; OIDC and other application HTTP clients are unchanged. RED-first tests on real `ExternalRfc3161TransportPolicy.CreateHandler` prove the original default was unsafe; CI and ADR [0055](../adr/0055-rfc3161-no-ambient-forward-proxy.md). This does not stop transparent forwarders, service meshes, malicious local TLS roots, DNS spoofing/rebinding, private IP DNS replies, or enforce connection-time identity. Production Azure/on-prem require audited firewall and egress restrictions to approved TSA destinations, and an independently reviewed proxy feature if one is ever required. QTSP historical Trusted List, chain/revocation, WORM and legal verification remain #15/#17/#13; pilot evidence remains `Unverified`.

## Delegated TSA connection-time DNS/IP destination pinning (#87; ADR 0056)

The previous name-based `ExternalRfc3161EndpointPolicy` blocked direct localhost/private-IP literals but **did not check DNS answers** when the .NET HTTP handler made a connection. A public-looking TSA hostname could resolve to RFC1918, 169.254.169.254 metadata, loopback, multicast, carrier-NAT, IPv6 ULA or other special-use addresses, including a mixed safe/unsafe DNS answer. Disabling forward proxies in #86 did not address that destination selection.

The dedicated `external-tsa` primary handler now uses `SocketsHttpHandler.ConnectCallback`: it validates the initial request URI/authority, resolves DNS **once for each newly created TCP connection**, refuses empty or mixed disallowed-address answers, and connects only to one of the approved public IP addresses directly (no second DNS lookup). The only exception is a trusted environment-gated **Development** loopback URL with exclusively loopback IP answers. Normal TLS hostname/SNI validation is not bypassed. This is not an operator-approved destination IP allowlist, a trusted DNS service guarantee, or an authenticated QTSP origin: a compromised resolver returning an attacker-controlled *public* address, a transparent service mesh, routing changes, malicious CA roots, and the reuse of previously established pooled connections remain separate threats. On-prem and Azure require independent network egress/firewall restrictions, controlled resolver, reviewed CA trust and explicit operator-approved TSA inventory. No change to legal qualification, WORM or `Unverified` evidence status. See [ADR 0056](../adr/0056-rfc3161-connect-time-resolved-destination-policy.md), [operator guidance](TSA_HTTP_TRANSPORT.md), parent #15 and #13/#17.

## Unbounded TSA pooled connection reuse and platform-negotiated legacy TLS (#88; ADR 0057)

After #87 introduced `SocketsHttpHandler.ConnectCallback`, only **new sockets** execute the RFC3161 hostname/DNS/public-IP vetting. By default, `PooledConnectionLifetime` was infinite; a healthy connection could be reused across subsequent timestamp requests without periodic checks of the configured TSA's changed DNS answers. The dedicated named `external-tsa` handler now sets a **60-second** pool connection age, causing expired idle connections to be retired and replacement sockets to rerun the DNS/IP policy. This is **not** a hard time limit for active requests or a trusted DNS/ownership guarantee.

The same handler now limits negotiated TLS versions to **TLS 1.2/1.3**, rather than the OS-selected `SslProtocols.None` default. This intentionally avoids accepting older TLS negotiation when the host policy would permit it, at the cost of reduced compatibility with out-of-date TSA servers and potential future-version upgrades. The platform's stock TLS certificate chain, hostname, SNI and root-store checks remain active, with **no custom validation callback**. TDD RED [CI 43915676967](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43915676967) and [ADR 0057](../adr/0057-rfc3161-bounded-connection-lifetime-and-tls-floor.md) track the change. A signed token could still have an unqualified/untrusted signer; historical EU Trusted List checks, certificate path/revocation, operator-approved public IP/egress allowlist, malicious public DNS answers, transparent intermediaries, WORM and legal CAB/AgID readiness remain **unresolved** under #15/#17/#13. Neither Azure nor on-prem may disable TLS peer verification to work around a noncompliant upstream TSA. Pilot evidence stays `Unverified`.

## RFC 3161 CMS signer with non-dedicated or ambiguous EKU (#89; ADR 0058)

The delegated RFC 3161 pilot previously verified cryptographic signature/imprint using .NET `Rfc3161TimestampToken.VerifySignatureForHash(..., out _)` and discarded the signing certificate. Microsoft's verifier requires timeStamping EKU inclusion, but RFC 3161 §2.3 additionally demands a **single critical EKU extension containing only id-kp-timeStamping**. A verifier accepting a mixed-use certificate without an explicit exclusivity check weakens the assurance that the signing key is reserved for TSA messages. TemporalMark now applies `ExternalRfc3161SignerCertificatePolicy` to the **verified signer certificate**, rejects missing/noncritical/duplicated/malformed EKU or extra/mismatched purpose OIDs, and fails closed before returning or persisting a response. Unit fixtures are disposable self-signed test certificates; no trust is inferred. TLS server certificates, current or historical EU Trusted List trust anchors, signer certificate chain/revocation and timestamp policy remain separate validations requiring #15; network egress and authenticated provider status remain unverified, WORM storage #17 and legal qualification dossier #13 remain OPEN. Pilot evidence remains `Unverified`. See [ADR 0058](../adr/0058-rfc3161-critical-exclusive-timestamp-signer-eku.md) and [operator guide](TSA_HTTP_TRANSPORT.md).

## Delegated RFC3161 self-signed or unapproved CMS signer leaf (#90; ADR 0059)

The existing RFC3161 parser verifies signed CMS/nonce/SHA-256 imprint and #89 enforces exactly one critical timeStamping EKU. Those checks are self-contained: **any** independently created self-signed leaf with that EKU could generate a cryptographically self-consistent timestamp response unless the operator binds issuance to the explicitly approved signer. A server-configured provider identifier or HTTPS transport certificate is not a cryptographic binding to the certificate signing the TSTInfo. The TSA provider now requires `TimestampProvider:SignerCertificateSha256` (SHA-256 of the full DER X.509 signing leaf), verified **before HTTP send** for syntax/absence, and compares it to the **actual CMS signer** returned by the cryptographic token verifier using `CryptographicOperations.FixedTimeEquals` after sole critical EKU. Null, malformed/empty/ambiguous pins prevent contact with the TSA; an unapproved signer certificate fails without recording the token. Only the operator's API configuration can set this value; disabled TSA needs no pin. This is not pinning the HTTPS certificate or silently trusting the first signer observed.

A compromised already-pinned TSA signing key, signer leaf reissue during planned rotation, malicious operator pin configuration or public DNS/routing attack can still cause failure or abuse. A single approved pin requires reviewed change-control and operator-confirmed certificate identity before rotation; no fallback or auto-discovery is available. **A leaf SHA-256 identity pin is not independent PKIX validation**, revocation at signing time, historical EU Trusted List service type/status, qualified TSU/UTC proof, trusted egress/firewall, WORM custody or CAB/AgID dossier: #15, #17 and #13 remain OPEN. Successful pin+signature+EKU checks still produce only `Unverified` pilot evidence. See [ADR 0059](../adr/0059-rfc3161-operator-approved-signer-certificate-sha256.md) and [operator guide](TSA_HTTP_TRANSPORT.md).

## Approved CMS signer issuing under an unexpected TSA policy OID (#91; ADR 0060)

The RFC3161 delegated provider previously accepted and persisted whichever `TSTInfo.policy` the pinned TSA signer returned; it did **not** request or enforce a specific service policy. A single TSA signer can potentially participate in different operational, test or unqualified service policies; a correct signature, imprint, signer pin and critical-only EKU **do not prove** the chosen timestamp service/policy was approved. The provider now requires a **server-owned, canonical numeric** `TimestampProvider:PolicyOid` before any HTTP send and includes it in signed protocol interaction as `TimeStampReq.reqPolicy`. After cryptographic verification and signer certificate controls, the expected OID is explicitly compared with the signed `TSTInfo.policy`, and any mismatch fails without producing a receipt. No tenant-controlled OID, implicit provider default, trust-on-first-use, or acceptance of noncanonical textual OIDs. This also protects against accidental wrong-service selection when the correct QTSP signer key is used.

This change cannot authenticate the **legal status** of the OID or convert an unqualified policy into an eIDAS-qualified service; an operator-approved incorrect OID, compromised pinned signer, historical revocation, untrusted certificate path, algorithm compromise, or malicious public DNS target remain separate risks. The operator must authenticate source policy documentation out of band and maintain reviewed changes for each deployment. Independent certificate chain/revocation and historical European Trusted List/service status remain parent #15; WORM evidence #17 and CAB/AgID legal qualification #13 remain OPEN. The persisted status continues as `Unverified`. See [ADR 0060](../adr/0060-rfc3161-operator-approved-request-and-signed-token-policy.md) and [operator runbook](TSA_HTTP_TRANSPORT.md).

## Untrusted RFC3161 CMS signer certificate path under a pinned leaf (#92; ADR 0061)

After #89–#91, the provider verified the RFC3161 CMS signature/imprint/nonce, critical sole timeStamping EKU, **operator-pinned signing leaf DER SHA-256**, and requested/signed policy OID, but did **not** validate that the signer actually chained to a separately operator-approved certification authority. A self-signed or illicitly issued leaf that was **mistakenly** pinned could still be accepted as pilot `Unverified` evidence. The delegated connector now additionally requires a *server-owned, independently reviewed* `TimestampProvider:TrustAnchorCertificateBase64Der`: one canonical DER X.509 self-issued CA root with critical CA BasicConstraints and critical KeyCertSign, checked **before HTTP send**. This setting is not derived from a tenant, TSA DNS, CMS reply, local OS root store or TLS peer. After signed CMS/imprint/nonce/EKU/leaf pin and signed policy checks, a fresh `X509Chain` verifies the *same actual CMS signer* under `CustomRootTrust` with only that CA certificate in `CustomTrustStore`. Only intermediates embedded in the actual CMS reply are accepted; missing/alternative local intermediates fail, and the verified path must terminate in the **exact reviewed DER anchor**. `VerificationFlags=NoFlag` prevents ignoring path/signature failures. The X.509 engine uses **current UTC** certificate validity, not verified historical genTime.

The policy sets `DisableCertificateDownloads=true` and `RevocationMode=NoCheck` explicitly: there is **no AIA issuer download, CRL or OCSP check**, and no inference that a certificate was unrevoked at receipt time or signed token time. This prevents unexpected network fetches/SSRF and maintains repeatability, but leaves independent historical revocation and EU Trusted List qualified-service status fully unresolved in #15. A compromised operator-approved root, erroneous root selection, compromised pinned leaf, imported malicious-but-authorized CMS intermediate, local clock drift and untrusted archive evidence are separate operational threats. Review approved anchors through an independent authentic channel, control root rotation and enforce network egress separately. Both on-prem and Azure use the identical policy. **Passing this chain check is NOT certification, QTSP status or eIDAS qualification**; pilot receipts remain `Unverified`, WORM #17 and legal dossier #13 stay OPEN. See [ADR 0061](../adr/0061-rfc3161-operator-approved-offline-signer-x509-chain.md) and [TSA runbook](TSA_HTTP_TRANSPORT.md).

## Stale/backdated/future RFC 3161 signed issuance time and wall-clock path substitution (#93; ADR 0062)

The #92 offline custom-root `X509Chain` originally evaluated the verified CMS signer's certificate path against **current wall-clock time** rather than the **TSTInfo.genTime included in that verified CMS**. A certificate could be valid at one of those instants but not the other. Moreover, a pinned TSA signer might sign a timestamp whose claimed `genTime` is far in the past/future and still satisfy CMS signature, hash/nonce, EKU, leaf SHA-256 pin, policy OID and chain checks. The live issuance provider now captures its own UTC clock just before HTTP transmission and immediately after reading the complete bounded reply. **Only after signature/nonce/imprint/signer/policy verification**, it checks that the signed `genTime` falls within **[request-start − 120 seconds, response-end + 120 seconds]**, inclusive. Extreme dates and backwards local clock transitions fail closed. The same bounded signed `genTime` is then required explicitly as `X509ChainPolicy.VerificationTime` on the offline custom-root chain for that verified signer; no implicit current-time default. Existing verified-CMS-only intermediates, no-system-CA, no-AIA, no-ignored-error and `RevocationMode=NoCheck` behavior remain.

The 120-second tolerance is a **pilot host-clock plausibility check**, not RFC 3161 certified `accuracy`, independent UTC(k) attestation, an audit of host NTP drift, trusted historic signing-time proof or revocation/status at `genTime`. A compromised approved TSA key or an NTP-compromised host could make plausible false timestamps inside the window; network delays, clock steps and time precision differences require operational detection. A valid chain at signed `genTime` says **nothing** about historical OCSP/CRL issuer revocation, EU Trusted List qualified service status or legal trust. The portal/operator must keep `Unverified` pilot state and parent #15/#17/#13 OPEN. See [ADR 0062](../adr/0062-rfc3161-live-gen-time-and-issuance-time-x509-path.md), [RFC 3161 §2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2), [TSA runbook](TSA_HTTP_TRANSPORT.md).

## Missing signer revocation evidence despite valid RFC3161 CMS, EKU, policy and signed-time X.509 path (#94; ADR 0063)

After #89–#93, an RFC3161 reply could satisfy strict DER/CMS signature/nonce/imprint, verified critical-only EKU, reviewed signer leaf SHA-256 pin, signed service policy, bounded `genTime` and independently approved root `CustomRootTrust` **even when the signer was listed as revoked**. `X509Chain` deliberately sets `RevocationMode=NoCheck` and must not be treated as a revocation validator. This limited pilot slice adds a **separate mandatory, operator-supplied, independently reviewed complete issuer-signed CRL** from server-owned `TimestampProvider:IssuerCrlBase64Der`, rejecting absence or malformed CRL **before contacting the TSA**. After validating the same actual signed CMS signer chain at signed `genTime`, it checks the verified signer is **directly issued by the approved CA root**, and refuses any root→intermediate→leaf path until every non-root path element has independent revocation coverage. The CRL signature must verify using that exact approved root RSA SHA-256 key; issuer DER name, root `CrlSign`, SKI/AKI and CRLNumber are checked. The signed full CRL must cover `genTime` through `thisUpdate <= genTime < nextUpdate`, and the leaf must **not appear anywhere** in the revoked serials. Matching but incorrectly signed CRLs, stale/not-yet-effective CRLs, unsupported delta/indirect/specialized CRL extensions or unknown critical semantics fail closed. No OS CRL cache, CRL Distribution Point network retrieval, open proxies or tenant-supplied CRL can satisfy this guard.

**Residual threats:** A *clean* complete CRL limited to one chosen issuer/distribution point is not proof that all CRL scopes or historical certificates have been evaluated: this first profile supports only direct root-issued leaf, complete v2 RSA-SHA256 CRL with a single AKI key identifier, CRLNumber and no entry extension semantics. It intentionally rejects multi-hop, reason-partitioned, delta/indirect and unsupported algorithms, rather than claiming success. A compromised approved CA/private key, substituted operator setting, stale but apparently current signed CRL, same-number equivocation/rollback and unauthenticated distribution channel remain operator/architecture risks requiring independent auditing and monotonic custody. **There is no persisted immutable CRL/OCSP proof, historical EU Trusted List service status or legally qualified claim.** `X509Chain.RevocationMode=NoCheck` remains explicit for chain path-only validation; the new CRL policy is separate. Pilot receipts remain `Unverified`; parent #15 and WORM #17/legal #13 stay OPEN. See [ADR 0063](../adr/0063-rfc3161-offline-direct-issuer-signed-full-crl.md) and [operator guide](TSA_HTTP_TRANSPORT.md).

## RFC3161 signer revocation across an intermediate CA (two complete issuer CRLs; #95, ADR 0064)

Before #95, the CRL validation in #94 covered only direct reviewed-root→TSA-signer chains; a root→intermediate→signer path was rejected because the root-issued CRL says nothing about the TSA signer issued by the intermediate. **#95 extends the explicitly covered path by one CA intermediate, without weakening the previous fail-closed boundary.** The live provider now extracts a **fresh, fully validated X509Chain** built from the actual cryptographically verified RFC3161 CMS signer, the exact operator-approved custom root and CMS-embedded intermediate material only. Its chain must have exactly 2 or 3 certificates. For a three-element chain, the independently approved root-signed complete CRL must show that the *selected intermediate CA* is not revoked; the separately approved intermediate-CA-signed full CRL must show that the *same verified TSA signer* is not revoked. Each check uses the issuing CA actually selected by PKIX path building, not an arbitrary CMS certificate with the same distinguished name, and enforces issuer cRLSign, signature under that CA's actual RSA key, CRL AKI matching CA SKI, CRLNumber, full CRL semantics and `thisUpdate <= CMS-signed genTime < nextUpdate`. A missing, wrong, tampered, expired or incomplete CRL, a revoked intermediate or leaf, or a path with two or more intermediates **fails issuance without fallback**. A directly root-issued signer still needs only its root CRL; a second configured but unused CRL fails to prevent ambiguous operator setup. Nonempty malformed optional intermediate CRL is rejected *before HTTP*, and neither Azure nor on-prem accepts tenant-controlled CRL bytes or unexpected network fetches.

**Residual and legally relevant trust gaps remain**: the new two-hop check is not general RFC5280 §6.3 coverage, comprehensive CRL distribution-point/reason partition assessment, delta/indirect/OCSP evidence, historical immutable signed CRL snapshots, independently witnessed rollback-resistant CRLNumber custody, EU qualified service historical Trusted List evaluation, independently proven UTC(k), CAB/AgID qualification or WORM. Existing X509Chain `RevocationMode.NoCheck` continues as a path-only validation flag; revocation is a **separate** two-hop signed-CRL policy. The operator must independently authenticate and review **both** issuer CRLs and record approved changes. **Keep parent #15, WORM #17 and legal #13 OPEN and receipts `Unverified`.** [ADR 0064](../adr/0064-rfc3161-intermediate-issuer-complete-crl-coverage.md) · [TSA runbook](TSA_HTTP_TRANSPORT.md) · [RFC5280 §6.3](https://www.rfc-editor.org/rfc/rfc5280#section-6.3) · [RFC10007 cRLSign](https://www.rfc-editor.org/rfc/rfc10007.html).

## CRLNumber rollback of a still-time-valid issuer-signed CRL (#96; ADR 0065)

Despite #94/#95 RSA SHA256-authenticated complete CRLs at every supported direct or one-intermediate issuer path, a privileged operator or attacker with deployment configuration write access might **replace a newer CRL with an older but still within its signed `thisUpdate/nextUpdate` validity window**. The signature, correct issuer DN, AKI/SKI and a clean serial check alone would not reveal that an earlier revocation snapshot was superseded. Per [RFC5280 §5.2.3](https://www.rfc-editor.org/rfc/rfc5280#section-5.2.3), the CRLNumber is a monotonic **per-issuer/scope** signed extension; it MUST be noncritical and verifiers must support values up to 20 octets.

The delegated provider now requires server-only `TimestampProvider:IssuerCrlNumberFloor` and, for a configured second CRL only, `TimestampProvider:IntermediateIssuerCrlNumberFloor` as **canonical positive decimal minima** from reviewed operator records. It rejects missing/noncanonical/inconsistent floors **before outbound POST**. The strict DER decoder preserves and validates the complete CRL's signed noncritical CRLNumber; after the selected issuer's RSA signature and all prior CRL checks, the root CRLNumber and (when applicable) intermediate CA CRLNumber must each be >= **their own** operator-approved floor. This prevents accepting a still-time-valid correctly signed CRL that lies **below a deployed floor**; a higher signed sequence is permitted. `BigInteger` prevents silent 32/64-bit overflow, and >20-octet CRL numbers or malformed/critical extensions fail closed. The existing CustomRootTrust chain, signed TSTInfo.genTime and direct/two-hop complete CRL semantics remain unchanged. No new external network fetch, tenant influence or Azure-only service.

**This is not independently held monotonic CRL history.** A malicious privileged deployment operator, compromised deployment automation, or restored old environment configuration can roll back **both** the signed CRL and its floor. Reuse/equivocation of the same signed sequence number, historical CRL loss, unauthenticated CRL source approval and scope/reason incompleteness also remain. Closing this gap requires a *separately administered* monotonic last-seen CRLNumber witness, signed log/custody with rollback-proof recovery, and archived independently verified issuer CRL evidence (parent #15/#64/#17). This does **not** check historical EU Trusted Lists, QTSP service qualified status or trusted UTC(k); receipts remain `Unverified` and #15/#17/#13 stay OPEN. See [ADR 0065](../adr/0065-rfc3161-operator-crl-number-minimum-floors.md) and the [TSA operator guide](TSA_HTTP_TRANSPORT.md).

## RFC 3161 signer end-entity Key Usage isolation (#97)

After signed RFC3161 CMS verification, TemporalMark explicitly checks that the **verified CMS signer certificate** (not an arbitrary embedded certificate) declares a single non-CA Basic Constraints extension and a single Key Usage with digitalSignature and/or nonRepudiation only. It rejects CA, CRL-signing, key agreement/encipherment, missing, duplicated or malformed certificate extension profiles. This is a strict **pilot-specific certificate encoding/usage acceptance gate**, not proof that the private key is exclusively held for timestamps or that the signature derives from a historically qualified QTSP. RFC 5280 does not universally mandate a Basic Constraints extension on all end entities; interoperability must be reviewed instead of disabling the guard. Existing single critical timeStamping EKU, signer fingerprint, signed policy, pinned PKIX path, full signed CRL verification and independent CRLNumber floor remain. No EU Trusted List qualification-history validation, independently immutable CRL/receipt custody, live QTSP interoperability, UTC(k), HSM custody, WORM/retention or CAB/AgID completion. Parent #15/#17/#13 open; receipts Unverified. See ADR 0066 and issue #97.

## Signed RFC3161 accuracy claim vs authenticated clock truth (#98)

The delegated pilot now checks `Rfc3161TimestampTokenInfo.AccuracyInMicroseconds` after verifying RFC3161 signature/nonce/imprint, strict signer EKU/KU, pin, policy, bounded `genTime`, custom-root path and issuer-signed full CRLs. A **signed claim** of accuracy <= 1 second and >= 0 is required; missing/large/overflow values are rejected. This is deliberately stricter than RFC 3161: `TSTInfo.accuracy` is OPTIONAL and may instead be documented under a verified TSA policy. The pilot has no policy-level substitution and must fail closed if real provider tokens omit it. A compromised TSA can sign a false accuracy, and the gateway's clock drift (allowance +/-120 seconds) is not a trusted UTC(k) calibration. No HSM/time-source telemetry, signed time-health window, EU Trusted List service qualification/history, independently authenticated CRL distribution, WORM proof or CAB/AgID evidence is supplied. On-prem and Azure retain identical checks. See ADR 0067/#98; keep #15/#17/#13 open and all records Unverified.

## External TSA truncated response / raw I/O diagnostics (#99)

After HTTP status/MIME acceptance, `ResponseHeadersRead` exposes an untrusted streaming body. A network peer or compromised upstream intermediary may terminate the stream after sending part of an ASN.1 DER payload or fail at stream acquisition. Without an explicit `IOException` mapping, unhandled raw low-level exceptions can yield an HTTP 500 instead of a stable 503 and may risk exposing provider/socket internals in operator logs/error formatting. `ExternalRfc3161TimestampProvider` now maps `IOException` to a fixed `TimestampProviderUnavailableException`; no partially read `ProviderTimestamp` can be returned. Malformed **complete** DER still produces a response error; genuine caller cancellation remains separate. Do not automatically retry when response delivery is uncertain: the remote TSA may have already consumed the nonce and issued/billed a timestamp, and no exactly-once reconciliation is implemented. No qualified legal trust, UTC(k), historical EU Trusted List, WORM preservation or independent immutable audit follows from transport error normalization. On-prem/Azure use the same provider. See ADR 0068/#99, with parent #15/#17/#13 still open.

## Uninterpreted CMS-signed TSTInfo extensions (#100)

RFC3161 §2.4.2 permits optional signed `TSTInfo.extensions`. A valid CMS signature authenticates the bytes but does not mean the receiver understands arbitrary OID meanings, extra timestamp service assertions or required processing rules. A signed token carrying even **noncritical** unknown extensions might be semantically misinterpreted if the API silently ignores them. The delegated *unqualified pilot* now enforces a deliberately strict no-TSTInfo-extensions profile **after** validating CMS signature/imprint/nonce, signer profile/pin, signed policy/genTime, custom-root issuer-signed CRLs and declared accuracy. Any nonempty signed TSTInfo extension list fails with a generic response error and no persisted evidence. This is **not** a claim that RFC3161 universally requires all clients to reject all such response extensions; the standard's unknown-request-extension rule primarily governs the TSA. A compliant QTSP may be rejected until explicit OID semantics, DER test fixtures, policy implications and historical trust status are independently reviewed. X.509 *certificate* extensions remain separately required. Shared on-prem/Azure behavior, no tenant allowlist or new privilege, V015/V016 registrar interlock unchanged, and all unqualified receipts remain Unverified. See ADR 0069/#100; #15/#17/#13 stay OPEN.

### Non-caller cancellation during streamed TSA response (#99 amendment)

The initial partial-stream hardening handled `IOException`, but a TSA
handler/content stream can also throw the base `OperationCanceledException`
(without caller cancellation), bypassing a `TaskCanceledException`-only
catch. That previously risked an unhandled API 500 instead of generic
transport unavailability. The provider now catches
`OperationCanceledException` **only when the caller's
`CancellationToken.IsCancellationRequested == false`**, maps it to
the existing generic TSA timeout/unavailability response and refuses
any partial DER. If a client cancels after data delivery begins,
the original cancellation continues outward without being fabricated
as an upstream failure. This does not prove no timestamp was created
upstream, prevent double billing or enable safe blind retries. Tests
cover upstream abort at send/acquire/partial-body and caller cancellation
mid-body. ADR 0068 amendment/#99; no legal qualified or WORM claim.

### TSA response-body disposal without IOException (#99 amendment)

A disrupted HTTP peer or handler can close an already acquired
`HttpContent` stream before the body is complete. A subsequent
`ReadAsStreamAsync` or `ReadAsync` can throw `ObjectDisposedException`,
which is **not** an `IOException`; without a narrowly scoped handler,
the API may surface an unhandled 500 or leak implementation details
instead of its stable 503 provider-unavailable boundary. The
`ExternalRfc3161TimestampProvider` now maps this exception to a
fixed unavailable error **only if the original caller token was not
cancelled**. No partial DER bytes are returned or persisted. This
does not prove that the remote TSA failed to issue or bill for a
timestamp, authorize blind retries or confer qualified legal status.
RED-first stream acquisition and partial-body disposal regressions
plus original caller cancellation test are tracked under ADR 0068/#99.
All records stay Unverified; #15/#17/#13 and the V015 registrar
interlock remain unchanged.

## Exact-commit CI status publication trust boundary (#101, ADR 0070)

GitHub Actions `CI` has four core jobs, but the connected GitHub API can
expose no push-triggered workflow runs for recent `main` SHAs. Without
another verifiable signal, an operator might incorrectly close issues based
on unobserved supposed GREEN runs. The reporting-only fifth `ci-verdict`
job uses `needs` to read **GitHub's four actual job results** and creates a
GitHub commit status `temporalmark/ci-4-core-jobs` on exactly `GITHUB_SHA`.
It publishes `success` **only** when all four explicit results are
`success`; failure, skipped, cancelled, missing and malformed dependencies
all fail closed. Its token is restricted to job-scoped `statuses: write`
plus read-only contents, with the pinned checkout not persisting credentials.
Other jobs remain `contents: read`. No issue/PR edit, remote execution,
Docker privileged credentials, new third-party action or release signing
capability is granted.

**Residual risks:** GitHub commit statuses are mutable, not signed CAB
attestations. Compromised GitHub runners/branch administrators or an actor
with commit-status write rights could forge a status. A canceled reporter,
network/GitHub API failure or inability to read a status means **UNKNOWN**,
not GREEN. A valid status for an *older* SHA, or a rerun on an old attempt,
does not verify the latest documentation-inclusive `main`. Operators must
match exact SHA/context/linked Actions run and independently inspect tests
when possible before closing child issues. This adds no qualified
timestamping, UTC(k), historical Trusted List, WORM or FIDO trust, and
does not alter the V015/V016 registrar interlock. See ADR 0070,
[operator guide](CI_VERDICT_COMMIT_STATUS.md) and issue #101 under #20.

## CI test-only signing certificate expiry vs actual identity-key validation (#102, ADR 0071)

An isolated FIDO MDS cryptographic **candidate** test had its disposable
`x5c[0]` signer leaf generated for a frozen 2026-11-16 fixture clock,
with NotAfter 2026-11-18 00:00 UTC. The maintained IdentityModel JWS key
validator then denied the real signed *positive* at 09:07 UTC on Nov 18,
despite the fixture's separately pinned X509Chain checking its synthetic
old `VerificationTime`. This was observed as **1 failing of 489**
Provisioner tests in [CI 44272815080](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44272815080/attempts/1).
A future attempt to make such tests pass by disabling issuer-signing-key
validation, permitting expired leaf certs or trusting host roots would
turn a legitimate negative security behavior into a false GREEN.

The fix is confined to the **test-only** disposable signing fixture:
derive its reference clock from current UTC at fixture initialization,
and add a test asserting the actual DER `x5c[0]` leaf remains valid
at the current runner time. Retain all negative expiration, wrong-root,
wrong-key and tamper cases. **Do not** connect this candidate to a real
registrar, API, SQL, FIDO root allowlist or grant. It still returns only
`UNAPPROVED / JWS_CHAIN_ONLY_REVOCATION_UNVERIFIED`; revocation of
the authenticated FIDO R46 signing chain remains #57/#55, V015/V016
registration stays blocked, and this is unrelated to legal QTSP/UTC(k)
qualification. See ADR 0071/#102.

## Ambiguous / oversized Base64 SHA-256 issue request (#103; ADR 0072)

The authenticated tenant-admin issuance JSON contains an untrusted
`digestBase64` string. The former `Convert.FromBase64String` call
ran **before bounding the text length** and tolerated alternative
spellings (including ignorable whitespace and potentially nonzero
unused padding bits). Multiple texts could represent the same digest,
risking inconsistent application-level comparisons and unnecessary
decoder allocations on large requests, even though the real RFC3161
message imprint is binary. The business service now rejects any input
other than the **canonical 44-character padded Base64 encoding of
32 bytes**, before any provider call or persistence, using a predecode
length limit and an ordinal re-encoding equality check. Errors do not
echo the submitted value. This *reduces input ambiguity and local
resource exposure*, but it does **not** prevent malicious administrators
from issuing repeated valid requests, guarantee upstream TSA idempotency,
mitigate DDoS before HTTP request buffering, verify historical EU
Trusted Lists, secure long-term WORM evidence or confer qualified
status. A separate server-side idempotency/quota ledger and ingress
body-size limits remain needed under open #15/#20. Same on-prem/Azure
business logic, no tenant bypass, WebAuthn V015/V016 stop-line unchanged.
See [ADR 0072](../adr/0072-canonical-sha256-base64-issuance-ingress.md).

## Confusing external TSA unavailability with malformed timestamp replies (#104)

A configured TSA or intermediate gateway can respond with HTTP
`408 Request Timeout`, `429 Too Many Requests`, `503 Service
Unavailable` or `504 Gateway Timeout` after receiving an RFC3161
imprint. Previously every non-200 response was treated like an invalid
response token and the API surfaced 502. The pilot now recognizes only
these four upstream **transport unavailability** statuses before MIME
or body processing and maps them to the existing generic API 503.
Other statuses remain untrusted/invalid and API 502; 200 still requires
strict RFC3161 DER/CMS and reviewed signer trust gates. The error body,
reason phrase and untrusted `Retry-After` header are never included
in returned error text or used to retry. This reduces operational
ambiguity and prevents upstream header/body disclosure.

**Outstanding security/operational risk:** an external failure response
does not prove the TSA did *not* issue or charge for the timestamp;
HTTP statuses themselves are not signed timestamp evidence, and an
attacker controlling the TSA could lie. No automatic retry, quota
inference, upstream reconciliation or idempotency protection is provided.
Those require independent reviewed issuance identifiers and accounting
under parent #15. On-prem/Azure share the identical code; SQL
registrar V015/V016 stays blocked, and the pilot remains `Unverified`,
not a QTSP-qualified service. See [ADR 0073](../adr/0073-rfc3161-upstream-http-unavailable-vs-bad-response.md)
and [#104](https://github.com/KeyserDSoze/TemporalMark/issues/104).

## Corrupt retained TSR digest or repeated receipt IDs in registry pages/ZIP (#105, ADR 0074)

The authenticated tenant admin listing endpoint previously accepted records
whose stored DER and SHA-256 did not match, because only the receipt download
and ZIP-writing code called `TimestampRecord.Validate()`. A compromised or
buggy repository could therefore surface corrupt token metadata in an
ordinary page. ZIP export also did not explicitly reject two records
with the same ID (manifest ambiguity and duplicate `tokens/{id}.tsr`
paths). Normal PostgreSQL primary keys prevent duplicates in an
uncompromised table, but the application must still distrust unexpected
repository results.

`TimestampRegistryService.PageAsync` and `ExportZipAsync` now both
prevalidate **tenant + requested UTC period**, each record's local
`TimestampRecord.Validate()` consistency check (including SHA-256 of
retained DER), and unique IDs **within the returned collection**, before
returning any page or assembling ZIP bytes. A mismatch fails closed.
This reuses shared C# code for on-prem/Azure and preserves tenant
authorization checks in OIDC/PostgreSQL. RED-first corruption and
duplicate-ID Business tests were actually observed failing in
[Actions 44281759576](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44281759576/attempts/1)
(232/236 Business passed, 4 expected failures) before the minimal fix.

**Residual risk:** SHA-256 matching an attacker-controlled stored hash
is self-consistency, **not authentic immutable storage**. A malicious
writer able to rewrite both token and hash, omit entire records, replay
complete DB backups, or forge an otherwise valid-looking archive still
evades these local checks. The service does not assert global
cross-page uniqueness, an atomic export snapshot, complete arbitrary
period exports beyond 10,000 records, independently signed manifests,
qualified QTSP trust, legal WORM/hold, or long-term verifier custody.
Parent #17/#15/#13 remain open; pilot records remain `Unverified`;
WebAuthn V015/V016 registrar stop line remains enforced. See
[ADR 0074](../adr/0074-registry-page-export-integrity-and-unique-ids.md)
and [runbook](REGISTRY_INTEGRITY_READ_GATES.md).

## Unbounded source DER volume in synchronous timestamp ZIP export (#106; ADR 0075)

The tenant-authenticated synchronous period export previously enforced
**at most 10,000 records** but placed no bound on the length of one
persisted `ResponseDer` or the **cumulative source DER bytes** being
compressed into an in-memory ZIP. A legacy oversized receipt or many
large, self-consistent records could amplify memory and CPU use,
even though newly issued delegated TSA responses are capped at 1 MiB.

Before allocating the ZIP or hashing retained DER, the application now
rejects **any source receipt exceeding 1,048,576 DER bytes** or **any
batch whose total source DER exceeds 67,108,864 bytes**, using a
long accumulator and guarded subtraction. The API maps the shared
`ExportTooLargeException` to a generic HTTP **413**, asking for a
smaller UTC interval. This is in addition to the existing tenant,
period, stored SHA-256, duplicate-ID and row-count checks, and returns
**no partial ZIP** if a limit is exceeded. The same C# service runs on
Azure and on-prem OSS. There is no new export bypass, SQL mutation,
credential grant, or WebAuthn V015/V016 registrar change.

**Not a complete resource defense:** the underlying Npgsql
`ForExportAsync` already reads and materializes data before this
guard; server concurrency, ZIP output size, decompression risks,
network transfer, and unbounded count across an entire period are
separate concerns. A local self-consistent hash, size bound and ZIP
manifest do **not** amount to independently sealed evidence, legal
WORM/object-lock, complete period export or QTSP-qualified timestamp
verification. Streaming/paged asynchronous exports and independently
signed manifests remain parent #17; QTSP trust and compliance remain
#15/#13. Pilot records stay `Unverified`. See
[ADR 0075](../adr/0075-synchronous-evidence-zip-byte-budget.md)
and the [registry operator runbook](REGISTRY_INTEGRITY_READ_GATES.md).

## Untrusted downloaded ZIP: offline structure and hash check without provenance (#107; ADR 0076)

A tenant administrator may copy a `temporalmark-period-export-v1` ZIP
outside TemporalMark. The original DB authentication, API checks and
export-prepare audit cannot prove the ZIP was not altered in transit
or afterward. Standard ZIP tools can silently accept duplicate
member paths, traversal names, renamed token files and ambiguous
duplicate JSON keys. A downstream importer could misassociate raw
TSR files and their declared hashes. The new **Python standard-library
offline checker** `tests/integration/verify_period_export.py`
never extracts files or contacts the network. It rejects extra/missing/
duplicate/unsafe/symlink ZIP members, duplicate manifest keys and
record IDs, bad count or path mappings, noncanonical 32-byte SHA-256
imprints, wrong token SHA-256, non-UTC/out-of-period timestamps
(compared at seven-digit 100ns precision), and pilot records claiming
a qualified or otherwise non-`Unverified` state. It bounds manifest
decompression to 8MiB, each DER member to 1MiB, aggregate DER to
64MiB, rows to 10000 and ZIP file size to 80MiB, checking announced
and actual lengths. Success reports **only local internal consistency**,
without exposing imprint/provider/tenant/token contents.

**This is not cryptographic archive authentication.** An attacker able
to change both the manifest and the DER bytes can produce another
self-consistent fake archive. ZIP CRC plus SHA-256 under an *unsigned*
manifest is not a signature, immutable high-water witness, audited
chain of custody, RFC3161/CMS signature verification, historical EUTL
service assessment or qualified timestamp validation. An exported
subset may omit legitimately issued marks while still passing
per-file validation. Source DB snapshot consistency, WORM/object-lock
retention and GDPR-approved legal hold are still missing under #17;
QTSP/provenance and CAB/AgID qualification remain #15/#13. The
tool's error path is generic to avoid leaking raw evidence paths and
values; unsigned status fields cannot authorize privileged actions.
See [ADR 0076](../adr/0076-offline-zip-structure-sha256-self-consistency.md),
[operator guide](OFFLINE_PERIOD_EXPORT_VERIFIER.md) and child #107.
No on-prem/Azure differences or registrar V015/V016 bypass are added.

## Ambiguous offline ZIP member compression and Unix special-file metadata (#108, ADR 0077)

The pilot's offline archive checker (#107) already validates expected
member paths and SHA-256 bytes, but untrusted ZIP central-directory
metadata can request alternative compression codecs or represent a
member as a Unix FIFO/device/socket/directory despite a normal
`tokens/{uuid}.tsr` name. Python `zipfile` can decode BZIP2/LZMA;
these are **not supported in the current TemporalMark .NET v1 export
profile** and should not be accepted merely because the library
supports them. Unknown methods are already handled generically by
the old `RuntimeError` catch (including `NotImplementedError`);
the new policy rejects unsupported compression **before reading**.
For Unix-origin ZIP members only unset file type or regular-file
metadata is permitted; FIFO, device, socket, directory and symlink
types fail closed without filesystem extraction.

The control leaves strict ZIP member naming, duplicate entries and
JSON keys, bounded decompression (80MiB outer ZIP, 8MiB manifest,
1MiB per DER, 64MiB total), UTC 100ns and internal SHA-256 checks
unchanged. New adversarial tests mutate both ZIP header method fields
and use crafted Unix external attributes; valid ordinary STORE/DEFLATE
files remain supported. Test-only source RED and implementation were
committed separately under [ADR 0077](../adr/0077-zip-compression-unix-special-file-gates.md)
and [#108](https://github.com/KeyserDSoze/TemporalMark/issues/108).
Early [Actions 44290472692](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44290472692/attempts/1)
ran **19/20** offline tests and failed the unsupported-method
*fixture* before invoking the parser due to incorrectly escaped PK
signatures; this was corrected without weakening the validator.
A real exact-final-HEAD GREEN is needed before closure.

**Residual risks:** coherent replacement of a manifest and matching
DER cannot be detected without independent authentication. None of
these ZIP metadata gates establish timestamp signature validation,
historical QTSP status, WORM/legal hold, export completeness, audit
custody or qualified trust. Parents #17/#15/#13 remain OPEN and pilot
receipts are `Unverified`; V015/V016 registrar remains blocked.

## ZIP local-vs-central header ambiguity in offline export verification (#109; ADR 0078)

A ZIP archive presents each member twice: in its *local header* and
in the *central directory*. The pilot's offline validator (#107/#108)
already checks central method/flags, member name and DER SHA-256, but
Python `ZipFile.open` does not ensure the local compression-method
field agrees with the central directory. This was reproduced with an
in-memory otherwise-valid DEFLATE archive: changing only the 16-bit
method at local offset +8 to unknown method 99 left `zipfile.read`
able to retrieve unchanged contents and CRC. Thus an internally
inconsistent file could pass a manifest/DER digest check despite
contradictory metadata; consumers might disagree about its format.

The verifier now reads **exactly 30 bytes** at every member's bounded
local-header offset *before any decompression*, checks PK local
header magic, and requires **local 16-bit compression method and
general-purpose flag word to equal the central-directory values**.
The existing central allowlist STORE/DEFLATE, encryption/symlink and
special-file denials, bounded reads/aggregate volumes, duplicate
member/JSON keys, UTC precision and SHA-256 checks remain in place.
Source-first tests mutate only local 16-bit fields (both manifest and
TSR), preserving central metadata, content and recorded digest, with
positive ordinary archives. The CLI continues to fail generically,
without echoing archive paths or imprint bytes. See
[ADR 0078](../adr/0078-zip-local-central-header-method-flag-binding.md)
and [#109](https://github.com/KeyserDSoze/TemporalMark/issues/109).

**Residual limitation:** even a perfectly matched local+central ZIP
header and SHA-256 manifest cannot authenticate a coherent malicious
rewrite of both unsigned manifest and DER. This does not assert real
RFC3161/CMS validation, historical EU Trusted List, qualified QTSP,
WORM legal hold, independently witnessed custody, complete coverage
of a requested period or CAB/AgID certification. Parent #17/#15/#13
remain OPEN, all pilot receipts `Unverified`, and WebAuthn V015/V016
registrar stop line is unchanged.
