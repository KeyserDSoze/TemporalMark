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

## Tenant-foreign or unbounded UTC-day dashboard aggregation (#110, ADR 0079)

The authenticated dashboard already showed total period counts via
`/api/v1/stamps/summary`, but client-side grouping of the first 50
`/stamps` rows would omit valid records beyond that page. A new
`/api/v1/stamps/daily` path instead uses a **single PostgreSQL
aggregate** which keeps both `organization_id=@org` and
inclusive/exclusive UTC date bounds in its `WHERE` clause and groups
by **`(issued_utc AT TIME ZONE 'UTC')::date`**, never a
PostgreSQL session-local date. `TenantAdminAsync` derives the tenant
from the verified bearer and live SQL membership, not an untrusted
request query/header/body. HTTP 401/403 gates and real two-tenant
Keycloak-signed/Pg CI canary probes cover this new route.

Daily statistics accept **only 1–31 full UTC days**, exact midnight
bounds, and reject invalid intervals before querying PostgreSQL.
The business layer refuses duplicate, negative/zero non-aggregate,
or out-of-window repository days; missing days are returned as zeros.
The React IT/EN chart shows these as **registry records, NOT verified
qualified timestamps**. For long periods it skips only the optional
daily-chart query, preserving the existing exact total, audit, registry
and export workflow. It neither reads raw document contents nor
exposes another tenant's evidence.

Residual risks: a compromised database owner can delete/create rows
and generate plausible aggregates; no signed/WORM audit, complete
historic period proof, independent high-water witness, quota/billing
reconciliation or legal qualified QTSP validation exists. Ordinary
tenant authorization still lacks production RLS, independently
approved privileged enrollment and CAB/AgID qualification. See
[ADR 0079](../adr/0079-tenant-utc-daily-dashboard-counts.md),
[operator guide](DAILY_DASHBOARD_UTC_COUNTS.md), child #110 and open
parents #14/#17/#13. No bypass to WebAuthn V015/V016.

## Stale tenant/period data and first-50-only registry browsing (#111; ADR 0080)

The authenticated admin dashboard used to render only the first 50
timestamps even when `/stamps/summary` reported more records; later
receipts could not be selected for individual download via the
browser. The existing .NET/PostgreSQL endpoint already had bounded
`offset,limit` and SQL predicates `organization_id=@org`,
`issued_utc>=@start` and `issued_utc<@end`. The frontend now
makes explicit 50-row offset requests with labelled Next/Previous
buttons, resetting offset when dates or the active access token
change. Page counting is based on the separately authorized total,
never on a tenant-supplied selector.

**Asynchronous response ordering:** overlapping React fetches for
different UTC intervals, page offsets or bearer tokens can finish out
of order. An old in-flight result could otherwise restore the wrong
page or retain previous tenant metadata visually after a new
authenticated session. A per-component monotonically increasing
request generation commits complete list/summary/daily/audit payloads
only when they belong to the latest load, and an access-token-linked
presentation gate hides previous session data. Invalid or failed
loads do not leave prior tenant records on screen. This does not
replace signed OIDC verification, live DB membership enforcement,
production RLS, MFA step-up or independent IdP role revocation.

**Tests and residual risk:** a real signed-Keycloak/two-tenant
PostgreSQL HTTP canary tests offset and limit bounds and tenant spoof
rejection. A separate authenticated browser fixture **mocks only
list/summary responses after real OIDC checks** to test 51 synthetic
rows, forward/back paging and late old-page responses. Mocked UI
paging does not establish SQL isolation or malicious-server
resistance. Offset pagination is not a stable point-in-time snapshot:
concurrent inserts/deletes can shift rows between pages. Full export
coverage requires signed high-water manifests and immutable custody
under still-open #17. Pilot stamps remain `Unverified` and
legal QTSP qualification/CAB #15/#13, production RLS/tenant approval
#14/#23 and WebAuthn V015/V016 interlocks remain unresolved.
See [ADR 0080](../adr/0080-admin-tenant-registry-pagination-and-stale-request-gate.md),
[runbook](REGISTRY_PAGINATION_UI.md), issue #111.

## Exact document-imprint search: sensitive fingerprint enumeration and tenant scope (#112, ADR 0081)

The authenticated registry formerly permitted listing by UTC period and
ID, but no exact **document SHA-256 message-imprint** lookup. Such
fingerprints can reveal a tenant's possession of or interest in
specific documents even though the original document is never sent
to TemporalMark. A naïve cross-tenant hash search or URL query would
enable hash-presence probing through the access logs, browser history,
proxy telemetry or foreign tenant records.

The new **read-only POST `/api/v1/stamps/search`** keeps
`digestSha256Hex` in the JSON body (rather than a GET URL),
requires the **same signed OIDC and active PostgreSQL tenant-admin
membership** used by existing registry endpoints, and derives
`organization_id` only from that verified principal/DB check.
The Business layer requires exactly **64 ASCII hex characters**,
canonicalizes to the stored 32-byte SHA256 Base64, and validates
offset >= 0 and limit 1–50 **before any SQL**. PostgreSQL constrains
`organization_id=@org`, half-open UTC period, SHA256 OID and
`digest_base64=@digest`, ordered by issuedUtc/id and limited to
51 fetched records for a 50-row page. The Business layer verifies
**every row including lookahead** for tenant, period, document
imprint/algorithm, uniqueness and stored DER SHA256 consistency
before returning only non-DER metadata. Invalid results fail closed.
No document content or raw token DER is returned by search.

Browser IT/EN search/Next/Previous uses no tenant selector and
invalidates old search results on new token, date or fingerprint.
It maintains existing audited receipt download as a distinct
authorized operation, not an implicit direct DER response from
search. The real disposable signed-Keycloak/Pg two-tenant CI test
checks own and foreign hashes, spoofed headers/body, signed/anonymous/
inactive callers and malformed hashes/bounds; mock-only browser
search UX tests do **not** substitute for these real SQL tests.
See [ADR 0081](../adr/0081-tenant-document-sha256-imprint-exact-lookup.md)
and [search operator guide](DOCUMENT_IMPRINT_SEARCH.md).

**Scoped #114/V018 mitigation:** successful authenticated searches now
append tenant, actor, action and UTC occurrence to the pilot audit
before any matches are returned. No searched imprint, match flag/count,
receipt ID or period is recorded; bad or unauthorized requests append
no tenant search events. PostgreSQL audit-write failure denies search
responses. Disposable signed-Keycloak/Pg A/B CI exercises the gate,
including a temporary runtime-role INSERT denial that is reverted.

**Scoped #116/V019 mitigation:** one shared PostgreSQL 17 primary
serializes tenant+principal quota checks using transaction-level tenant
advisory locks, fixed 12/actor and 30/tenant per UTC 60-second bucket.
Signed-OIDC active tenant-admin and strict input preflight precede quota;
denial returns 429/Retry-After without match data, failed shared primary
fails closed, and neither raw imprints nor JWTs are quota keys. The runtime
role cannot directly SELECT/DML rate tables; SQL schema owner can change
quotas and remains a sensitive privilege. Actor subjects are personal data
and need independent retention/deletion beyond opportunistic cleanup.

**Outstanding under #115/#113/#17:** this ordinary PostgreSQL pilot audit
is not tamper-evident WORM. The limiter requires a shared writable primary,
not multi-primary regions; fixed-window boundaries allow short bursts.
No verified edge/pre-auth throttling, independently approved privacy
retention/DPIA, separate signed audit custody or production reverse-proxy
request-body redaction has been delivered.
A reverse-proxy configured to log request bodies may still leak
hashes despite POST. Confidential document imprints, correlation
between known document hashes and tenant results, overbroad admin
roles and database owner tampering remain high-priority risks.
Search is **not** independent RFC3161 CMS validation, qualified QTSP
proof, historical EUTL trust, signed WORM manifest, complete
all-time snapshot or eIDAS/CAB/AgID approval. Parent #14/#17/#15/#13
remain OPEN and pilot evidence remains `Unverified`. No registrar
V015/V016 or cloud-specific exemption.

## Web Nginx access event privacy — scoped #117 / ADR 0084 (NOT full ingress logging governance)

The previously inherited Nginx `combined` access format includes `$request` (raw request line with URL query) and client IP/referrer/user-agent. Even when an intended `POST /api/v1/stamps/search` keeps a document imprint in JSON, malicious or legacy clients may still send an imprint, token or customer identifier in the URL, Referer, User-Agent or other headers. The same compiled web image is referenced by Docker/on-prem and Azure Container Apps; see [ADR 0084](../adr/0084-minimized-nginx-imprint-search-access-log.md) and [operator guide](NGINX_ACCESS_LOG_PRIVACY.md).

For the **web Nginx container access stream only**, a static `http`-scope `temporalmark_minimal` format is now used explicitly at web server scope. The allowed event has a fixed marker, numeric HTTP status, method and duration; no URI/path/query, request body, bearer/cookie, client IP, subject, tenant, referer, agent, or search result. CI first proves RED against the missing config, then runs source policy tests and a real pinned Docker/Nginx HTTP canary probe which fails if the raw synthetic URL/query/referrer/agent/fake bearer/JSON document imprint appears in any captured web-container log. The test does **not** exercise all exceptional error paths or real production logging.

**Residual release blockers:** Azure Container Apps external managed ingress access diagnostics and Log Analytics, separate CDN/WAF/proxy or on-prem operator overrides, Nginx error logs for exceptional requests, Kestrel/API and IdP exception traces, third-party instrumentation, per-tenant subject retention, backups and GDPR-DPIA decisions are not proven safe. No production log retention policy, independent signed WORM custody, edge/preauth rate limiting, eIDAS qualification or CAB/AgID approval follows. #115/#113/#17/#13/#15 remain OPEN; V015/V016 registrar interlocks remain frozen; pilot evidence remains `Unverified`.

## Idle search quota actor-ID cleanup — scoped #118 / ADR 0085

V019 stores exact authenticated OIDC `sub` values as principal rate-counter keys. Its opportunistic deletion only runs on subsequent valid searches; an inactive tenant's short-window actor IDs could therefore persist indefinitely despite the evidence/receipt retention purpose being legally distinct. A **forward-only V020** now introduces a manually owner-invoked, bounded PostgreSQL function `public.purge_stale_imprint_search_rate_counters(integer)` to remove stale tenant/principal counters even without new traffic. It enforces the same strict greater-than-three-minutes old UTC-window cutoff as V019, limits deletion to 1..500 per table, uses nonblocking row locks, denies PUBLIC/runtime/provisioner/approver/credential registrar EXECUTE and returns **aggregate counts only**, no identifiable `sub`, tenant UUID or document metadata. Distinct fresh/idle CI tenant rows and a tenant search-audit event are checked to ensure retained pilot audit and evidence are not touched; runtime unauthorized invocation must fail.

**Residual privacy release blockers:** this does not run without a separately authenticated and authorized owner command, does not establish a GDPR storage limitation schedule or a right-to-erasure implementation, has no independently approved deletion cadence/alerts, and does not purge PITR backups, external query/trace logs, Azure-managed ingress or lawful holds. Schema/backup owners can still extract or alter source rows; `SKIP LOCKED` can defer rows until a later authorized execution. A real production retention/DPIA, secrets/DB-owner segregation, backup expiry, scheduled reconciliation and operational proof remain OPEN under #115/#113. The user-selected indefinite timestamp evidence retention is a separate purpose and was **not** modified by V020. #17 sealed custody and #13/#15 eIDAS/QTSP qualification remain unresolved, with V015/V016 reviewer/registrar freeze and `Unverified` pilot status unchanged. See [ADR 0085](../adr/0085-bounded-owner-imprint-quota-cleanup.md) and [operator guide](IMPRINT_RATE_COUNTER_CLEANUP.md).

## ASP.NET Core API normal HTTP request diagnostic minimization — scoped #119/ADR 0086

Nginx `temporalmark_minimal` access logs (#117) do **not** control the upstream ASP.NET Core request-start and routing categories, independently configurable HTTP logging middleware, error/exception traces or external API telemetry exporters. Unexpectedly sensitive material in a caller's URL, query, referrer, user-agent, Authorization or body could be copied to those downstream logs, especially if request HTTP logging is later enabled. Microsoft .NET 10 [HTTP logging options](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/http-logging/?view=aspnetcore-10.0) expose per-field recording, including potentially personal information.

**Scoped mitigation:** the shared API binary installs programmatic logging filters to suppress ordinary `Information`/`Debug` request-start and endpoint-routing messages, and explicitly sets `HttpLoggingFields.None` with the `HttpLoggingMiddleware` and W3C logger categories set to `None`; `UseHttpLogging` / `UseW3CLogging` are not enabled. Disposable Docker CI sends synthetic path/query/referrer/user-agent/fake bearer/SHA256-shaped JSON requests and checks the **actual API container stdout and stderr** contain no synthetic canary bytes. Ordinary bearer 401 and unexpected route 404 remain unchanged. This does **not** modify the PostgreSQL #114 audit trail (which must still persist before disclosing search results), #116 tenant quotas, WebAuthn V015/V016 interlock or recipient evidence retention.

**Residual:** application Error/Warning including authentication failure and DeveloperExceptionPage stack traces, arbitrary third-party/custom `ILogger` exception messages, outgoing HTTP instrumentation, OpenTelemetry/APM/log processors, Azure-managed ingress and Log Analytics, IdP/Keycloak logging and proxied Nginx errors, backups, legal privacy retention/DPIA, operator-defined providers/filters and hardware/network packet capture are **not independently attested**. Passing disposable API stdout checks is not a production full log non-disclosure guarantee. Keep #115/#113/#17/#18/#13/#15 OPEN; pilot records remain `Unverified`. See [ADR 0086](../adr/0086-api-request-diagnostic-log-minimization.md), [API log operator guide](API_LOG_PRIVACY.md).

## Azure OCI manifest digest-only application deployment admission — scoped #120 / ADR 0087

Prior to #120, Azure Terraform input values for API and web Nginx images were unconstrained strings, and the checked-in example used mutable `:tag` references. Even when the disposable Docker CI verified the code-owned request log controls (#119) and minimal Nginx access events (#117), retargeting a mutable registry tag could deploy a different API/web image on Azure from the one inspected. The shared on-prem OSS build remains unchanged by this Azure input policy.

**Scoped mitigation:** Azure Terraform now requires `api_image` and `web_image` to be OCI SHA-256 *manifest digest* references of the form `registry/repository@sha256:<64 lowercase hex>`, rejecting tag-only, unversioned, missing, short/nonhex/uppercase and mixed `tag@sha256` input. Actual Terraform `plan`-only tests with a mocked AzureRM provider (no Azure credentials, state, resource apply or remote API) exercise **one positive and ten negative cases** and fail CI if Terraform stops enforcing them; the example values are clearly FAKE. This policy reduces tag drift but does not authenticate the publisher, validate a signature/SBOM or prove the selected digest actually runs on Azure. See [ADR 0087](../adr/0087-azure-image-oci-sha256-digest-admission.md) and [operator checklist](AZURE_OCI_DIGEST_IMAGE_GUARD.md).

**Residual release blockers:** release registry ownership, signed OCI provenance/admission, transparency/SBOM mapping, supply-chain vulnerability scanning, multi-architecture digest choice, private ACR identity, real managed Container Apps pull/deployed revision proof and immutable artifact custody require separate tests/change approval under #18. Azure managed ingress/Log Analytics request metadata/privacy and cross-proxy diagnostics remain unresolved under #115/#113. No approved DPIA, QTSP/eIDAS legal qualification, WORM/sealed evidence or WebAuthn V015/V016 registrar release is supplied. Pilot evidence remains `Unverified`.

## CI-only OAuth/OIDC callback collision and exact redirect control — scoped #121 / ADR 0088

A previous docs-inclusive Azure OCI gate #120 CI [run 44643616282](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44643616282/attempts/1) failed **before any MFA browser login** because the disposable reviewer callback server could not bind `127.0.0.1:45678` (`EADDRINUSE`). The Azure mocked Terraform plan tests 11/11, .NET/Playwright, PostgreSQL 81/81 and logical restore, and container Nginx/API privacy canaries all passed; the CI four-core status was correctly published as **failure**, so #120 was not closed.

Under [ADR 0088](../adr/0088-disposable-mfa-loopback-callback-fallback.md) / [#121](https://github.com/KeyserDSoze/TemporalMark/issues/121), **only the isolated disposable Keycloak test client** has an explicit allowlist of `127.0.0.1:{45678,46678,47678}/oidc-mfa-callback` URLs (with full `http://` scheme); no OAuth redirect wildcard, production URI or network-wide listener is added. The real reviewer browser binds a permitted loopback port sequentially, skips only `EADDRINUSE`, aborts if all registered ports are occupied and sends the exact selected URI both in the authorization request and the subsequent code+PKCE exchange. The disposable CI wrapper **deliberately binds 45678** throughout the reviewer browser run to force the approved fallback. Backend source tests require exact realm/browser/CI allowlist alignment and forbid unregistered ephemeral bind. The separate registrar callback `45679` is unmodified.

**Security invariant:** OTP enrollment is not MFA proof; the browser still verifies fresh password+TOTP after a fresh login with failed-invalid-TOTP check; signed JWT issuer/audience/ACR/auth_time and live current-role .NET gates must pass. HTTP localhost and test credentials are not production IdP policy. Port collision fallback is not evidence of authentic human factor/device possession, reviewer consent, FIDO/TSU qualification or legally sealed signed custody. #20/#18/#115/#113/#17/#13/#15 and V015/V016 remain OPEN. See [CI operator runbook](CI_MFA_CALLBACK_COLLISION.md).

## Azure OIDC issuer malformed/tricky-input admission — scoped #122 / ADR 0089

The reference Azure Container Apps API receives `Authentication__Authority` from Terraform `var.oidc_authority`; previously a simple `startswith("https://")` admitted bare `https://`, local loopback addresses, URL userinfo/credentials and query/fragment values, despite OIDC Discovery requiring an HTTPS issuer with host/optional port/path and **no query/fragment**. This was a configuration-input weakness, not proof of a previously deployed unauthorized identity or successful token forgery.

**Scoped mitigation:** Azure Terraform input validation now requires a syntactically anchored HTTPS DNS-style FQDN with optional numeric port and nonempty path segments, rejects local/IP hosts, userinfo, query, fragment, empty/dot path elements, trailing slash and whitespace, with 3 accepted / 14 rejected **mocked Terraform plan-only** scenarios and existing 11 OCI digest tests; see [ADR 0089](../adr/0089-azure-oidc-issuer-input-validation.md) and [runbook](AZURE_OIDC_ISSUER_GUARD.md). The test does not fetch discovery, validate JWKS, verify DNS/PKI against an approved IdP inventory or deploy to Azure, and the reference regex intentionally excludes certain valid issuer encodings pending review. An attacker-controlled FQDN can pass syntax. The Nginx PWA embeds a **separate OIDC authority at build time**; its approved value must be independently reconciled with API runtime issuer and deployed image digest.

**Residual release blocker:** trust in issuer identity and tenant binding, live account revocation, signer/key rollover/claims, Entra-specific identity assurance, operational WAF/ingress and log privacy/DPIA, actual Azure image pull and signed artifact provenance remain open #18/#25/#28/#31/#115/#113. This is not QTSP/eIDAS certification, independent WORM custody or consent attestation. Pilot timestamp evidence `Unverified`; WebAuthn V015/V016 reviewer/registrar freeze unchanged.

## Azure reference ingress privacy gate — scoped #123 / ADR 0090

Prior to #123 the Terraform Azure Container App web/PWA had `ingress.external_enabled=true` **unconditionally**, so an initial reference apply could create an Internet-accessible web endpoint while the project explicitly lacked a provisioned WAF, verified Azure-managed ingress log redaction/retention, approved access policy, DPIA and CAB release. The API ingress was already internal; application request-log privacy #117/#119 and OCI digest pinning #120 did not prevent early public exposure.

**Scoped mitigation:** `var.enable_public_web_ingress` now defaults to **false**. In real mocked AzureRM Terraform `command=plan` CI, web and API ingress must both be internal by default, never allow insecure HTTP, preserve Nginx 80/Kestrel 8080 target ports, and suppress the misleading public `frontend_url` output (null). Only a deliberate `true` setting makes **web** externally accessible, never API; tests require API internal and HTTPS-only in both modes. This is a software change-control trigger, **not proof of independent approval**. See [ADR 0090](../adr/0090-azure-private-default-web-ingress.md), [operator runbook](AZURE_PRIVATE_INGRESS.md), and Microsoft's [ACA ingress model](https://learn.microsoft.com/en-us/azure/container-apps/ingress).

**Residual threat:** app internal ingress is a Container Apps **environment boundary**, not an unconditional private VNet endpoint or gateway firewall; a separately configured external environment route could still publish an internal app. A public web option true **does not install** Front Door/WAF, validate managed ingress telemetry, sanitize exceptions, limit pre-auth/edge abuse, protect Log Analytics retention, prove DNS/TLS/identity or approve GDPR-DPIA. Azure actual plan/apply, independent network probes and signed evidence remain unverified. #18/#115/#113 stay OPEN for production network/privacy; #17/#13/#15 and WebAuthn V015/V016 security/qualification stop lines unchanged. Pilot evidence remains `Unverified`.

## Azure Container Apps environment public IP / internal load balancer — scoped #124 / ADR 0091

The earlier app-ingress scope [#123](https://github.com/KeyserDSoze/TemporalMark/issues/123) set web and API `external_enabled=false` by default, but `azurerm_container_app_environment.main.internal_load_balancer_enabled` was **unset**. The AzureRM provider documents a **public-addressed environment** by default when this flag is not enabled, independent of each app's internal ingress. That left unnecessary public-environment network surface and an ambiguous safety assumption despite successful app-ingress mock plans and #117/#119 Nginx/API container log canaries.

**Scoped mitigation:** the Azure reference now explicitly sets `internal_load_balancer_enabled = !var.enable_public_web_ingress` on the same delegated VNet infrastructure subnet. **Default/explicit false** produces an internal environment LB plus internal web and API; **explicit true** produces an external environment with public web app but keeps API ingress internal; both app ingresses reject insecure connections. The `frontend_url` output remains null by default. New **real mocked Terraform `command=plan`** CI tests assert default and explicit-private environment mode and public-opt-in network mode, in addition to prior #123 app-ingress 3/3, #120 OCI 11/11 and #122 OIDC 17/17. Real [RED CI 44702387661](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44702387661/attempts/1) demonstrated that the previous environment setting failed its default-private assertion. [ADR 0091](../adr/0091-azure-internal-container-app-environment.md) and [network operator runbook](AZURE_INTERNAL_ENVIRONMENT.md).

**Residual:** an internal-load-balancer ACA environment is **not** a complete private network / endpoint access policy and may require separately reviewed VNet private DNS and routing. Existing environment internal/external conversion can require replacement, causing downtime, state changes and DNS cutover; no safe automatic migration is claimed. With `enable_public_web_ingress=true`, the environment and web become public without this template installing WAF/Front Door, CAB approval, ingress HTTP/log-data minimization or pre-auth edge controls. No real Azure plan/apply, packet-level path tests or Log Analytics privacy/DPIA are performed by the provider mock. #18/#115/#113 remain OPEN, as do independently signed WORM #17, eIDAS/QTSP #13/#15 and V015/V016 reviewer registrar stop lines; pilot evidence stays `Unverified`.

## Evidence Blob public-network exposure and Private Link isolation — scoped #125 / ADR 0092

Before #125, the Azure evidence Storage Account disabled anonymous Blob/container access, Shared Key and weak TLS but did **not** explicitly deny public network endpoint traffic. The existing ACA VNet had **no Blob Private Endpoint or linked private DNS zone**. That left a network exposure surface despite logical access control, and an Azure-release assumption was unsupported by previous CI.

**Scoped mitigation:** Azure Storage Account `evidence` now explicitly sets `public_network_access_enabled=false` and `https_traffic_only_enabled=true`, retaining `min_tls_version=TLS1_2`, disabled Shared Key/anonymous access, Blob versioning and deliberately unlocked immutability. A separate nondelegated `10.40.3.0/24` subnet hosts `azurerm_private_endpoint.evidence_blob` (Blob subresource, automatic owned-account connection) with `privatelink.blob.core.windows.net` zone, VNet link and DNS zone group; the existing ACA `10.40.1.0/24` and PostgreSQL `10.40.2.0/24` delegated subnets remain separate. The container resource is ordered after private endpoint/DNS and the AzureRM provider uses `storage_use_azuread=true` for its data-plane operations because Shared Key is disabled. New **real mock-provider Terraform plan** tests prove planned network denial and Blob private wiring; actual [TDD RED CI 44712716132](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44712716132/attempts/1) demonstrated missing public-network denial and absent HTTPS-only declaration. Intermediate mocked GREEN [CI 44713430656](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44713430656/attempts/1) proves **2/2** private storage plan cases plus previous **34/34** Azure plans. See [ADR 0092](../adr/0092-private-azure-blob-evidence-network.md) and [Blob private-network operations](AZURE_EVIDENCE_BLOB_PRIVATE_LINK.md).

**Critical remaining threats:** `azurerm_storage_container` creation accesses the Azure Storage **data plane**; a public GitHub runner ordinarily cannot reach that plane once public access is disabled. A real apply therefore needs controlled **VNet-connected Terraform runner**, private DNS, approved endpoint, valid Azure AD Storage Blob RBAC and staged provisioning; no mock plan proves it works. Private DNS can also affect name resolution for other storage accounts. Actual ACA-to-Blob PUT/GET, DNS/IP reachability, endpoint approval, data-plane roles, WAF/managed ingress log minimization, GDPR-DPIA/backup retention, locked independent WORM witness and qualification require independent tests and approvals under OPEN #18/#115/#113/#17/#13/#15. No legal custody/qualified timestamp certification or release of V015/V016 WebAuthn reviewer/registrar. Pilot evidence remains `Unverified`.

## Azure private Blob evidence operator preflight (ADR 0093, #126)

Terraform mock plans do not prove actual PE approval, DNS behavior or Entra access. A read-only, manually invoked private-runner preflight now fails closed on public/anonymous/Shared Key exposure, wrong PE target or status, dedicated subnet/NIC mismatch, DNS that yields an unexpected public/private IP, inherited HTTP(S) proxy routing and failed Azure CLI Entra Blob LIST. The CLI never performs evidence writes, prints blob identifiers or echoes Azure CLI diagnostic output. **Residuals:** a compromised runner or its DNS, another execution location, app managed identity RBAC, true Blob PUT/GET, external public denial, WORM retention and Azure managed log collectors remain unverified; run from an independently approved, monitored private runner and preserve separately controlled audit evidence. The tool is not a WORM or qualified-TSA attestation.

## Azure API DB connection value in Terraform state and external Key Vault reference (#127 / ADR 0094)

Previously Azure Terraform's Container Apps `api.secret.value` directly accepted the registry connection string and thereby entered sensitive state despite `sensitive=true`. The new Azure reference accepts only a **specific approved versioned Key Vault secret URI**, with a separate full vault ARM ID and fail-closed cross-vault precondition; the **value itself is created externally and never queried/written by Terraform**. The API has a bootstrap **user-assigned managed identity** for Key Vault `Secrets User` on the approved dedicated vault; its preexisting system-assigned Blob writer remains. AzureRM Terraform mock-plan tests enforce the intended configuration and reject invalid URIs/cross-vault scope. **Threats still open:** existing state/backups may contain old plaintext credentials; rotate and protect all historical copies under approved policy. Vault RBAC scope grants access to all secrets in that vault, so use an independently approved single-purpose vault; verify public/private Vault firewall, DNS, RBAC propagation and secret status on real Azure. **PostgreSQL administrator password remains in Terraform state** through `var.postgres_password`. Dynamic rotation, Entra-only database administration, safe Terraform state migration, Azure provider warning deprecation, managed logs, backup retention and GDPR/DPIA remain unsolved under #18/#115. No Azure deployment, real Key Vault read, independent WORM retention, or qualified service evidence is established by CI.

## Azure PostgreSQL Entra-only new-server candidate boundary (#129 / ADR 0095)

An isolated **non-deployed** Terraform candidate at `infra/azure/candidates/entra_postgres` declares a separate candidate-named PostgreSQL 17 server with `authentication.password_auth_enabled=false`, explicit Entra-only tenant, dedicated existing private subnet/DNS, a group Entra administrator and candidate database ordered after admin provisioning. Mandatory tests use `mock_provider "azurerm"`, and independent source-policy tests ensure no `administrator_login`/`administrator_password` or SQL credential variable is declared. Terraform mock computed SQL admin attributes cannot be asserted null from a plan and no Azure state or resources are created.

**Residual threats / release blockers**: existing Azure reference still puts `var.postgres_password` in Terraform state; prior state/backups and remote access may expose admin credentials. SQL owner, migration, restricted approval/registrar CLI roles and API runtime still require planned Entra token acquisition/rotation, Entra PostgreSQL role mapping and least privilege. The actual group object ID, membership/MFA, delegated subnet, DNS reachability, auth-mode restart/downtime, PostgreSQL session/token expiry, row access, backup/restore and state/credential migration are unverified. Do not apply this candidate, disable an existing SQL admin or migrate a real database without independent review and a separate audited change under #128/#18. WAF/privacy/DPIA and independent signed WORM/QTSP/eIDAS remain open.

## Detached Npgsql 10 Entra token data source security boundary (#130 / ADR 0096)

A new **unused-by-production** `EntraPostgresDataSourceCandidate` in Infrastructure constructs a token-only Npgsql data source with a caller-supplied trusted async delegate. The audience is pinned to Microsoft's PostgreSQL Entra scope; synchronous `Open()` is denied and async per-new-physical-connection password provider retrieves a fresh opaque token without storing it in a connection string. Configuration guard rejects unapproved non-Azure/loopback/multihost or raw IP database host, non-5432 ports, absent reviewed role/database, literal SQL passwords/passfiles, TLS below `VerifyFull`, and GSS preferred by Npgsql 10. A blank/failed token supplier returns fixed sanitised error without propagating bearer content in the original exception; explicit cancellation is preserved. Npgsql 10 `ContainsKey` checks supported keywords, so the adapter uses explicitly present `Keys` (observed in RED/GREEN tests) to avoid dropping the positive valid case.

**Risk boundaries:** These are pure .NET unit tests with fake access tokens, not evidence of DNS/IP/private Azure routing, real TLS certificate validation, Entra audience/expiry/role authorization, token refresh/revocation, PostgreSQL role permissions, pooled session revocation or successful data-plane login. The current API/Provisioner/migration scripts still use SQL credential-based authentication, and the Azure Terraform root **still puts `postgres_password` in Terraform state**. A later approved runtime switch must prove actual token acquisition and expiry, fail-closed partial DB outage, last-admin invariant and two-tenant signed HTTP isolation; preserve on-prem password-capable OSS deployment and control old state/history. WAF/managed-log GDPR privacy, independent WORM/legal integrity and QTSP remain open (#128/#18/#115/#17/#13/#15).

## Azure Container Apps local identity service and PostgreSQL token boundary (#131 / ADR 0097)

A **detached, nondeployed** .NET `ContainerAppsPostgresManagedIdentityCandidate` adapter now constrains token-acquisition requests to explicit ACA loopback HTTP `IDENTITY_ENDPOINT`, with `X-IDENTITY-HEADER` supplied separately and a pinned, approved **user-assigned** client GUID. Production HTTP transport bypasses all proxies, denies redirects, cookies and decompression, and connects to loopback IP literals instead of DNS (mitigating DNS rebinding and remote SSRF); the request uses the exact Microsoft PostgreSQL resource and API version, never caller/tenant-selected resource, token header in URL or default system identity. Responses larger than 32 KiB, non-200 HTTP status, wrong `resource`, token type, UAI `client_id`, invalid/near-expiry/far-future `expires_on`, control characters in token, or malformed JSON fail closed with a fixed exception and no secret-bearing inner exception. Explicit cancellation passes through; no retry, cache, shared token or SQL credential fallback. Unit tests use fake HTTP and fake tokens only.

**Unverified production threats:** local platform `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` provenance and rotation; Container Apps main-container identitySettings; same-pod or same-user local process spoofing; real MI tenant/SQL role/grants and audience signature; migration DDL authorization, Npgsql pool session expiry/revocation and token race; PostgreSQL TLS cert/CA/private DNS; monitoring and failover under rotation, header leakage or partial IAM outage. No actual API/CLI/SQL migration wiring nor Azure apply. Existing Azure Terraform `postgres_password` remains in live/historical state, and no remote-state purge or credential rotation has occurred. WAF/DPIA/privacy, WORM/independent evidence and eIDAS/QTSP remain separate #128/#18/#115/#17/#13/#15 blockers.

## Detached PostgreSQL runtime UAI Terraform pilot, separation of identities (#132 / ADR 0098)

An **isolated, not applied** Terraform root now declares one distinct candidate user-assigned managed identity for PostgreSQL **runtime** only, with an explicit approved `-pg-mi-candidate` name, pre-existing reviewed RG and region, no-auto-deploy and NOT_QUALIFIED tags, `prevent_destroy`, and nonsecret ARM resource, Entra `client_id` and service-principal `principal_id` outputs. Mandatory real mock-provider Terraform plan tests check positive scope and name/tag identity plus negative collision/bad name; Python source policy rejects auto Container App attachment, ARM RBAC/SQL grant, privileged Entra admin, SQL password or production root import. **No actual identity is created or granted access.** The main API Blob system identity, Key Vault UAI and independently controlled database administrator Entra Group remain separate, and SQL schema/DDL migration/reviewer/registrar role boundaries are not silently combined. See [ADR 0098](../adr/0098-isolated-postgres-runtime-managed-identity-candidate.md), [operator runbook](AZURE_POSTGRES_RUNTIME_UAI_CANDIDATE.md).

Residual high risks: any real apply without CAB and verified directory ownership; identity creation confused with SQL principal authorization (Azure RBAC does not grant PostgreSQL SQL rights); use of client ID instead of object principal ID for SQL mapping; identity attachment to a wrong Container App or inherited system identity; token exposure/expiry/active pooled sessions; migration owner/schema grants; DNS/TLS/private networking; current/historical Terraform state containing `administrator_password=var.postgres_password`; emergency decommission with `prevent_destroy`; preservation/independent WORM, GDPR-DPIA and QTSP. #128/#18 and broader #115/#17/#13/#15 remain OPEN; no Azure or legal-qualified state is established by mocked plans.

## PostgreSQL runtime effective privilege preflight (#133 / ADR 0099)

The previously detached Npgsql/Entra candidates now have an optional **read-only PostgreSQL session privilege preflight** (not connected to active API or any cloud deployment). Using a bound expected login and PostgreSQL `pg_roles`, `pg_has_role(..., 'MEMBER')` and `has_*_privilege`, it rejects superuser/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS, public-schema/database CREATE, organizations/memberships mutation, legacy bootstrap EXECUTE, or direct/transitive access to provisioner, approver, credential-registrar, pg_monitor/pg_read_all_data/pg_write_all_data/pg_execute_server_program/pg_read_server_files/pg_write_server_files and optional Azure `azure_pg_admin`. Requires positive runtime-group and minimum application SELECT/INSERT ACLs. Real Docker PostgreSQL 17 xUnit exercises authorized application login and denies migration owner, provisioner and approver without writing data, mutating SQL GRANTs or changing 20 migration checksums. Fixed error with no inner exception prevents catalog/SQL credential leakage; preserve cancellation. See [ADR 0099](../adr/0099-detached-readonly-postgres-runtime-privilege-preflight.md) and [operator runbook](POSTGRES_RUNTIME_PRIVILEGE_PREFLIGHT.md).

**Residual critical risks:** preflight is a disconnected one-session, point-in-time and non-exhaustive capability, not automatically enforced on production API/CLI. It cannot prove actual Entra service principal/token/SQL role mapping, unchecked extra roles/security-definer functions or future grant drift, pool revocation, RLS/ownership, private TLS/DNS, or Azure migration owner/registrar separation. Current Azure PostgreSQL admin password persists in Terraform state and snapshots. #128/#18/#115/#17/#13/#15 still OPEN for approved access policy and credential/state custody, WAF/DPIA, independent WORM and eIDAS/QTSP legal requirements.

## Explicit API Entra PostgreSQL pre-listen fail-closed startup gate (#134 / ADR 0100)

Previously separate Azure Npgsql #130, ACA local token #131 and live SQL privilege #133 code paths are now composed into **one explicitly operator-selected** .NET API mode `RegistryPostgres:AuthenticationMode=ContainerAppsEntraCandidate`. The default password-mode/OSS on-prem SQL datasource remains unchanged; wrong/unknown mode does not silently fall back. In Entra mode the API requires ASP.NET Production, an independently approved specific **user-assigned** client GUID, fixed expected SQL runtime role matching connection `Username`, ACA process `IDENTITY_ENDPOINT`/`IDENTITY_HEADER` (not appsettings), passwordless canonical Azure PostgreSQL hostname/port, SSL VerifyFull and GSS disabled. It must acquire an actual token/open a SQL session and run the **existing read-only effective privilege preflight** *before binding HTTP*, within 15 seconds, or abort with sanitized exception and **no SQL password downgrade**. Data source and hardened loopback HTTP token supplier have explicit shutdown disposal. Published API executable negative-mode tests and fake secret-canary log probes guard source-policy wiring. See [ADR 0100](../adr/0100-explicit-api-entra-postgres-prelisten-privilege-gate.md) and [runbook](API_POSTGRES_ENTRA_PRELISTEN_CANDIDATE.md).

**Still unverified/high risk:** a Production ASP.NET environment is only a programmatic guard, not CAB authorization. No real Entra PostgreSQL user, SQL GRANT, UAI-to-ACA attachment, private TLS/network, identity token lifecycle or PostgreSQL pooled-revocation test is delivered; one-session startup ACL scan cannot prevent future privilege drift. Privileged Provisioner/approver/reviewer/registrar CLI and migration runner remain password-auth with separate policies, not automatically Entra-aware. **Current Azure main Terraform still stores `administrator_password=var.postgres_password` in current/historical state.** Do not apply Terraform blindly, lift SQL privileges or claim production/eIDAS qualification; #128/#18 remain OPEN with #115/#17/#13/#15 privacy/WORM/QTSP stop lines.

## SQL fixed-UTC-minute search quota test boundary / false security regression prevention (#135 / ADR 0101)

V019 rate limiting is **12 per principal / 30 per tenant per fixed UTC epoch-minute determined by the PostgreSQL primary's `clock_timestamp()`**, not a rolling lookback. A workload may legitimately issue requests in two adjacent minutes at their shared boundary. A prior unchanged real PostgreSQL CI test sometimes mistook this for 31st-request admission in the *same* minute; [Actions 44824634172](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44824634172) observed 94 PASS/1 FAIL of 95 without logged server bucket data, so the historical precise cause remains **not forensically established**.

Scoped [ADR 0101](../adr/0101-postgres-verified-epoch-minute-quota-test-evidence.md) and [#135](https://github.com/KeyserDSoze/TemporalMark/issues/135) add **test-only** bounded three-attempt same-epoch-minute verification using the real SQL server clock and fresh disposable tenants; existing principal 12th/13th and aggregate 30th/31st denial, real SQL actor/tenant `hits`, 72-session concurrency, separate-tenant isolation and future clock rollback/fault-denial expectations remain strict. Separate real PostgreSQL test seeds previous-minute exhausted counter rows using the **test migration-owner** credential (not API runtime) and verifies new-minute reset through the unchanged restricted runtime SQL function. There are **zero** changes to V019/V020 contents, SQL role ACLs, authenticated claim source, POST API, logging, Azure Terraform, TSA evidences or migration checksums. A failed SQL privilege/admission test is not reclassified as a time flake; repeated bucket crossings exhaust the test budget and cause failure.

**Residual abuse risk:** fixed-window quotas can admit bursts on both sides of a UTC minute boundary; no sliding-window guarantee. Production edge/pre-auth rate limiting, multi-primary consistency, Azure managed ingress/Log Analytics and operator-proxy logging, personal OIDC principal retention/erasure, DPIA and legal approval remain **OPEN #115/#113**. This testing improvement does not establish WORM, qualified timestamping or eIDAS/QTSP status (#17/#13/#15).

## Search imprint JSON resource budget and anonymous-oversize containment (#136 / ADR 0102)

`POST /api/v1/stamps/search` previously relied on broad Kestrel/Nginx default body ingestion sizes even though a legitimate request is one 64-hex SHA-256 imprint, two UTC time bounds and pagination. Hostile unauthenticated clients could submit large JSON before JWT authentication/model binding, and rejected Nginx 413 error events could leak a malicious original query/URI to stderr despite the minimized **access** log. Scoped [ADR 0102](../adr/0102-scoped-imprint-search-body-budget-kestrel-nginx.md) / [#136](https://github.com/KeyserDSoze/TemporalMark/issues/136) adds **4,096-byte** exact-search POST limits at **both** direct API Kestrel (including future Azure managed ingress bypassing Nginx) and the pinned Nginx frontend web image (on-prem + Azure reference), with no modification to other request handlers or SQL V019 quota/role logic. ASP.NET Core sets `IHttpMaxRequestBodySizeFeature.MaxRequestBodySize` before JWT/model binding, instantly returns generic no-store HTTP 413 for declared oversized bodies and caps actual reads for chunked/unknown Content-Length; absent/read-only feature fails closed. Nginx exact location `client_max_body_size 4k` rejects known 4097-byte bodies before upstream, preserves the only minimal access event, and suppresses `error`-severity original request-line logging on **this sensitive location only** with `error_log /dev/stderr crit`. Lower-severity location diagnostics are deliberately lost, a security/operations tradeoff.

Mandatory source tests, disposable live port 8080 Kestrel + port 3000 Nginx HTTP probes (4096 accepted past size cap then 401, 4097 -> 413, no fake canary in output), and genuine **Keycloak-signed JWT chunked oversized body -> 413** prevent only Content-Length checking from being mistaken for full enforcement. Existing active membership, tenant A/B 401/403, bad imprint 400, quota 429/Retry-After, search audit, full SQL restore and WORM/qualification stop lines remain unchanged.

**Do not claim anonymous flood mitigation:** repeated 4KiB requests, ingress buffering, slow/incomplete chunked reads, connection/TLS exhaustion, long-term IP quotas, public CDN/WAF, Azure managed ingress exceptional logs, all egress/third-party telemetry, data erasure/backups and privacy DPIA are not proven by this scoped change. Nginx chunked discard edge cases may still consume bandwidth even if Kestrel enforces read size; operator-configured Nginx error logs outside the exact route are unverified. #115/#113/#18/#17/#13/#15 remain OPEN. No eIDAS, QTSP or signed immutable custody inference.

## Managed-identity PostgreSQL token response duplicate-key ambiguity (#138 / ADR 0103)

Azure Container Apps' local managed-identity endpoint supplies credential-bearing JSON to the optional Npgsql Entra SQL candidate. The existing .NET `JsonElement.TryGetProperty` API chooses the **last** definition when a property occurs multiple times. A malicious or compromised same-container local endpoint could return conflicting `access_token`, `expires_on`, `resource`, `token_type` or `client_id` (including case aliases) to exploit differences among decoders. [ADR 0103](../adr/0103-aca-identity-token-duplicate-json-fields.md) / [#138](https://github.com/KeyserDSoze/TemporalMark/issues/138) requires a 32 KiB-bounded parsed response to have **unique top-level JSON names with ordinal case-insensitive comparison before extracting any token**; even matching repeated values fail closed. Unique optional response fields remain compatible; general errors remain fixed and do not expose token, platform header or private host. RED-first mocked xUnit tests verify the former parser accepted 11 ambiguous scenarios; no live Azure endpoint, SQL grant or Terraform resource was changed.

**Residual:** This is only parser ambiguity hardening and does not cryptographically verify tokens in the .NET caller, isolate a malicious local process, attest actual ACA behavior, prove PostgreSQL Entra directory mapping, TLS/private route, SQL role revocation or token-pool lifecycle, or erase Terraform-stored admin passwords. Real production/cloud CAB #128/#18 and eIDAS/WORM/DPIA release gates #115/#113/#17/#13/#15 remain OPEN.

## ACA local identity response-body availability boundary (#139 / ADR 0104)

The optional API `ContainerAppsEntraCandidate` previously sent `HttpClient.SendAsync(ResponseHeadersRead)` with ten-second `HttpClient.Timeout`, then read a 32 KiB-capped local ACA JSON body with only the caller cancellation token. [Microsoft .NET 10 HttpCompletionOption](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpcompletionoption?view=net-10.0) states that the client timeout ends after headers in this mode; a faulty/compromised local process could return HTTP 200 headers promptly and stall the body indefinitely when the caller token was uncancelled. Size and connection-time limits alone do not bound this occupancy.

Accepted [ADR 0104](../adr/0104-aca-token-full-response-deadline.md) / [#139](https://github.com/KeyserDSoze/TemporalMark/issues/139) enforces one fixed monotonic ten-second linked cancellation budget covering headers **and** the complete streaming token body. Explicit caller cancellation propagates, internal timeout preserves generic no-inner no-retry no-secret-leak behavior. In-memory xUnit simulates stalled bodies, headers and caller cancellation through an isolated short test-only deadline. **Residual:** actual ACA platform semantics, same-container compromise, live Entra SQL grants and pooled-session revocation, independent failover, Terraform administrator password state, CAB production readiness, GDPR-DPIA, WORM and eIDAS/QTSP remain unverified. Parent #128/#18 and #115/#113/#17/#13/#15 remain OPEN.

## Generic Npgsql PostgreSQL bearer-token callback shape and cancellation (#140 / ADR 0105)

The Npgsql 10 optional token-only PostgreSQL datasource accepts a caller-supplied async credential delegate. Before #140 it rejected only blank tokens; a flawed future supplier could return arbitrarily long, whitespace/control-bearing or non-ASCII token strings, which the generic adapter might forward as PostgreSQL password material. A supplier that ignores a caller cancellation could return a bearer even after the request was cancelled. Existing concrete ACA supplier checks were **not** sufficient proof that every possible future callback maintained the same boundary.

[ADR 0105](../adr/0105-npgsql-token-shape-cancellation.md) / [#140](https://github.com/KeyserDSoze/TemporalMark/issues/140) now impose a second independent **1–16,000 printable ASCII** credential bound and check the caller cancellation token **again after awaiting the callback**, before handing a token to Npgsql. Invalid credentials cause the fixed no-inner generic failure; explicit caller cancellations propagate. A genuine RED-first GitHub test-only `main` run [44911738586](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44911738586) failed 10/635 scenarios for malformed, oversized and cancelled-returning tokens before the code change. The code never logs raw token/exception, caches credentials, defaults to an ambient Azure identity, alters SQL roles or enables Terraform cloud deployment. **Residual:** this syntactic bound cannot authenticate an actual Entra token, live SQL grant, expiry/revocation, DNS/TLS chain, compromised managed-identity provider, Npgsql pooled connection or SQL-password history. Parent #128/#18 and privacy #115/#113, WORM #17 and eIDAS/QTSP #13/#15 gates remain OPEN.

## PostgreSQL evidence/audit mutating ACL misgrant at API Entra prelisten (#141 / ADR 0106)

The opt-in Entra API's pre-listen database privilege probe previously verified required INSERT on the timestamp registry and tenant audit but did not deny UPDATE, DELETE, TRUNCATE, TRIGGER or REFERENCES on these append-only pilot tables; a role with an independently mistaken grant could therefore pass. A narrower UPDATE/REFERENCES grant on a single column is also an issue missed by table-only privilege inspection. [ADR 0106](../adr/0106-postgres-append-only-acl-prelisten.md) and [#141](https://github.com/KeyserDSoze/TemporalMark/issues/141) add ten no-write, no-exception-detail, effective SQL ACL denial predicates: has_any_column_privilege for UPDATE/REFERENCES and has_table_privilege for DELETE/TRUNCATE/TRIGGER on both tables. Genuine PostgreSQL 17 real-role TDD [RED 44914409424](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44914409424) exposed 14 cases accepted incorrectly by the old code (99 prior cases passed). Tests create and clean up uniquely generated logins without changing shared GRANTs or immutable schema migrations.

**Residual:** one-time checks cannot prove future SQL privilege drift, owner/DDL rights, independent WORM, retention, qualified eIDAS custody, real Azure Entra identity mapping or database/session revocation. #128/#18 cloud/CAB, #17 WORM, #115/#113 privacy and #13/#15 QTSP remain OPEN.

## Tenant org/membership unexpected PostgreSQL column-level grants (#142 / ADR 0107)

The nondefault Entra PostgreSQL runtime prelisten ACL check previously ruled out table-wide UPDATE/INSERT/DELETE/TRUNCATE on `organizations` and `organization_memberships`, but not a separately granted **column UPDATE**, table/column **REFERENCES**, or table **TRIGGER**. A future SQL misconfiguration could allow a runtime account to pass the prelisten gate with rights inconsistent with the tenant-admin integrity model. Official PostgreSQL 17 [privilege inquiry functions](https://www.postgresql.org/docs/17/functions-info.html) specify `has_any_column_privilege` checks either table- or any column-specific grants, unlike `has_table_privilege`.

[ADR 0107](../adr/0107-postgres-tenant-invariant-acl-prelisten.md) / [#142](https://github.com/KeyserDSoze/TemporalMark/issues/142) add exactly six read-only SQL denials across both tenant tables, without altering the existing password-mode/on-prem default, SQL GRANTs or migrations. Genuine PostgreSQL 17 RED-first [CI 44915914633](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44915914633) observed **8 expected missing-denial assertion failures** in the new disposable-role tests. Total RED run also contained **4 unrelated PostgreSQL connection slot 53300 failures** from accumulated per-generated-login test pools; production/source/test patch [fa3a581](https://github.com/KeyserDSoze/TemporalMark/commit/fa3a581c1521104e0ccd38b62391b1737e084a27) disables pooling ONLY in the disposable test-role fixtures (#141/#142), not application connections. Actual application privileges cannot be inferred from mock Azure tests. **Residual:** point-in-time gate, incomplete ownership/DDL/default ACL, privileged SQL operator and `SECURITY DEFINER` review, post-start drift, tenant invariants #14, real Azure #128/#18, independent WORM #17, privacy #113/#115 and QTSP/eIDAS #13/#15 all remain OPEN.

## Anonymous search burst/throttle and IP-topology boundary in shared Nginx (#143)

The shared, pinned Nginx web image's search POST location previously limited *body size*, not *frequency*, before JWT parsing. An anonymous client with a fake JWT could produce many upstream 401s without ever consuming the distributed V019 authenticated actor/tenant SQL quota. [ADR 0108](../adr/0108-nginx-preauth-imprint-search-peer-burst.md) / [#143](https://github.com/KeyserDSoze/TemporalMark/issues/143) add a **per-instance, per-network-peer** Nginx limit_req zone keyed to the directly connected binary peer address (not spoofable X-Forwarded-For), only for exact `/api/v1/stamps/search`. Its local 429 response provides Retry-After 1 and no-store, with suppressed request-line-bearing error diagnostics; upstream SQL 429 is passed through unchanged. RED-first [real Docker #44920497866](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44920497866) proved missing preauth cap before implementation.

**Residual risks:** one frontend replica's in-memory address bucket is not distributed across Nginx replicas, regions, direct API listeners or actual Azure managed Container Apps ingress. Real upstream NAT/ingress may collapse many legitimate tenants into one peer address; source client IP cannot safely be established from arbitrary forwarded headers. A determined attacker can use many source IPs or slow connections, and Azure managed ingress/logging may capture sensitive context independently. The limiter state is transient potentially personal network metadata; GDPR-DPIA, production traffic capacity, safe proxy topology, incident procedures, #115/#113 external gateway logging/retention and #17 WORM custody remain OPEN. No timestamp is qualified by this control.

## Mixed-case path alias bypass of Nginx search-only anonymous peer limit (#144 / ADR 0109)

ASP.NET Core 10 uses case-insensitive route matching but the original Nginx sensitive search route selected only exact lowercase URI (`location = /api/v1/stamps/search`). An anonymous `/api/v1/StAmPs/SeArCh` query could match the generic `/api/` proxy prefix and reach the *same* JWT-protected Kestrel search handler without Nginx's **own** 2r/s burst12 429 and Nginx-specific 4KiB/crit-error-log rule. Direct Kestrel's separate 4KiB limit, JWT and SQL 429 remain intact; this was a **proxy pre-auth resource/log defense bypass**, not an OIDC tenant authorization bypass. Official [Nginx core matcher](https://nginx.org/en/docs/http/ngx_http_core_module.html) and [ASP.NET Core 10 routing](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/routing?view=aspnetcore-10.0) describe the case semantics.

[ADR 0109](../adr/0109-nginx-case-insensitive-sensitive-search-route.md) / [#144](https://github.com/KeyserDSoze/TemporalMark/issues/144) use the anchored full-path **case-insensitive** Nginx matcher `location ~* ^/api/v1/stamps/search$` while keeping the same body/quota/error-suppression/proxy/log statements and both backend static source policies. Real pinned Docker [RED-first Actions 44922360150](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44922360150) observed lower-case quota 429 success then **no** mixed-case 429 across a separate 48-request burst. The minimum source fix is [`f5e953a`](https://github.com/KeyserDSoze/TemporalMark/commit/f5e953a1ccb9c57a4ec4aa7db2b7912f397b773c). Residual: other URI aliases and external proxy rewrites remain unassessed; one Nginx container's peer quota can be bypassed by direct API, replicas or untrusted fronting proxies, and shared ingress addresses can group distinct tenants. All real Azure edge, privacy/DPIA, signed custody and QTSP/eIDAS guarantees remain #115/#113/#18/#17/#13/#15 OPEN.

## Scoped early 414 Nginx privacy/cache gate (#145 / ADR 0110)

- [x] Reviewed ADR 0001/0084/0102/0108/0109, Nginx 1.27 HTTP vs location context, RFC 9110 heuristic cacheable 414 and existing #117/#136/#143/#144 real Docker privacy gates. Opened [#145](https://github.com/KeyserDSoze/TemporalMark/issues/145); accepted [ADR 0110](../adr/0110-nginx-early-414-cache-and-http-error-privacy.md) **before** source/tests.
- [x] Genuine real Docker [RED tests-only main `5288111`](https://github.com/KeyserDSoze/TemporalMark/commit/528811126bc629f1038e0280fd7cb0a33c725c2e), [CI 44925916344](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44925916344): `414` returned but **no** `Cache-Control:no-store`; previous Nginx access/privacy/413 and backend/frontend/terraform succeeded. Actual 414 minimal access method was `-` due to incomplete request parsing; no synthetic data in actual web logs. [ADR refined on main `751a41c`](https://github.com/KeyserDSoze/TemporalMark/commit/751a41cfe8bd9de261ebeb9ab2db22e21e3089e6) **before source**: do not suppress unrelated HTTP error diagnostics globally when no leakage was observed.
- [x] Minimal [source `7af6550`](https://github.com/KeyserDSoze/TemporalMark/commit/7af65503764a8e92d78992c835465e2aa93b1103): Nginx HTTP-scope 414-only map + server conditional Cache-Control header, three mandatory Python source-policy tests and new actual Nginx fixed-loopback 414/no-store/no-canary test in Docker CI. Preserve three-field access log, 200 SPA caching, other 413/429 and JSON/SQL/Auth/MFA unchanged. [runbook](NGINX_EARLY_414_PRIVACY.md).
- [ ] Close #145 only after exact **docs-inclusive final main SHA** all GitHub four core jobs and ci-verdict + combined `temporalmark/ci-4-core-jobs=success`, real 414/413/429, PostgreSQL 20 migrations/restore and signed Keycloak MFA/two-tenant 401/403. Parents #115/#113/#18/#17/#13/#15 remain OPEN; no Azure ingress/DPIA/eIDAS/WORM release claim.

## Search quota table direct ACL drift visible at Entra prelisten (#146)

The Entra-candidate API's one-time read-only PostgreSQL runtime ACL inspection used to cover protected organizations/memberships and registry/audit, but not V019 counter tables; a mis-granted SQL runtime LOGIN could pass with direct SELECT of `actor_subject_id` or INSERT/UPDATE/DELETE/TRUNCATE/TRIGGER/REFERENCES rights on `public.imprint_search_rate_principals` and `public.imprint_search_rate_tenants`. [ADR 0111](../adr/0111-search-quota-sql-acl-prelisten.md) / [#146](https://github.com/KeyserDSoze/TemporalMark/issues/146) now add 14 read-only effective table and any-column ACL restrictions, with 18 independent disposable-role PostgreSQL17 RED-first tests; [Actions 44935299721](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44935299721) confirmed all 18 missing-denial failures prior to source modification. Denial of runtime direct access does **not** itself prove SQL owner custody/privilege immutability, prevent post-start grants, stop direct SQL by a compromised database owner, protect default on-prem Password mode, solve privacy subject-retention/backup erasure or ensure a shared writable primary across regions. This is a narrow startup drift screening for a *nondefault* Entra API candidate. Real Azure SQL principal mapping/grants, #128/#18, search abuse/DPIA #115/#113, WORM #17 and QTSP/eIDAS #13/#15 remain OPEN.

## Accidental direct SQL function EXECUTE grant to runtime (#147)

The explicit Entra-candidate API prelisten previously rejected privileged provisioner/approver/registrar **role membership** but could pass when the application runtime LOGIN was accidentally granted `EXECUTE` **directly** on V006 SECURITY DEFINER request/approve/complete enrollment, V009 approver-only read, V013 legacy registrar issue (subject to V015/V016 interlocks), or owner-only SECURITY INVOKER V017 metadata stage and V020 stale-identity cleanup. A direct grant to a SECURITY DEFINER routine can bypass intended SQL role separation; a direct grant to a SECURITY INVOKER owner-only routine is a privilege-policy breach but does not independently grant DML. [ADR 0112](../adr/0112-privileged-function-execute-postgres-prelisten.md) / [#147](https://github.com/KeyserDSoze/TemporalMark/issues/147) add seven `pg_catalog.has_function_privilege` denials only to the point-in-time read-only Entra startup query, preserving the runtime `consume_imprint_search_rate` EXECUTE and all prior table/column, group and bootstrap restrictions. **Actual PG17 RED [44942023228](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44942023228)** showed **7 missing-denial failures / 139 other passes** before [source fix `4877bc0`](https://github.com/KeyserDSoze/TemporalMark/commit/4877bc003c7a9798f10035bf0ca67a095638c580). Owner/ALTER/DROP privileges, post-start ACL drift, future SQL functions, live Entra UAI grants, separately signed human/Keycloak identity approval and legal WORM/eIDAS/GDPR retention remain unresolved #128/#14/#50/#17/#18/#13/#15.

## Direct runtime EXECUTE on restricted reviewer decision routines (#148)

The #147 PostgreSQL startup SQL privilege check covered seven sensitive functions, but missed **two further V010/V012 SECURITY DEFINER review routines** (`reject_enrollment` terminal transition; `issue_reviewer_decision_challenge` unsigned challenge creation). An accidental per-login EXECUTE GRANT may grant a runtime SQL identity reviewer-owned functionality without `temporalmark_approver_group` membership. In real PG17 tests-only [RED 44949665078](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44949665078), both newly granted functions were incorrectly accepted by prelisten (2 failed denial assertions, 146 prior passes). [ADR 0113](../adr/0113-reviewer-function-execute-prelisten.md) adds two read-only typed effective ACL denies **only** in explicit Production Entra-candidate startup; no function is executed by the checker. Residual: PostgreSQL owner can override grants, post-start ACL drift is undetected, default on-prem password-mode does not run this gate, unsigned SQL review bypass and trusted human proof remain #38/#35/#31, real Entra PostgreSQL #128/#18, eIDAS/WORM #17/#13/#15.

## Direct API runtime read/write ACL on pending tenant enrolment and unsigned reviewer challenge data (#149)

Even after #147/#148 deny direct EXECUTE on reviewer-only SECURITY DEFINER functions, the explicit Entra API prelisten lacked effective ACL restrictions on V006 `organization_enrollment_requests` and V012 `organization_decision_challenges`. An extra direct SQL runtime LOGIN GRANT could expose issuer, operator/admin subject, reviewer metadata, digest or random challenge nonce with a **single-column SELECT**, or tamper with data using UPDATE/INSERT/DELETE/TRUNCATE/TRIGGER. Ordinary table ownership is already migration-owner, and V012 explicitly revokes base access, so this is a hypothetical **ACL drift/misgrant** gap, not evidence of an Azure production attack. Real PG17 [real PG17 Actions 44952204344](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44952204344) proved **18 missing-denial assertion failures / 148 prior passes**; [ADR 0114](../adr/0114-enrollment-review-table-acl-prelisten.md) adds fourteen fixed effective table/column privilege denials to the one-time read-only prelisten on an authenticated runtime SQL session. Residual: owner can change grants after startup, wrong production SQL role may be configured, API default Password mode is outside this gate, unauthorized SQL owner could alter data anyway, no signed reviewer decision or trusted WebAuthn enrollment (#38), independent WORM/qualified TSA/QTSP (#17/#13/#15) or live Azure Entra cutover (#128/#18).


## API runtime SET ROLE pivot through arbitrary elevated PostgreSQL NOLOGIN membership (#150)

Earlier Entra prelisten only inspected the authenticated **current** SQL login's five elevated role attributes and membership in a finite named set of PostgreSQL/Entra admin groups. In PostgreSQL17 `SUPERUSER`, `CREATEDB`, `CREATEROLE` and similar role attributes are not inherited; however, a SQL LOGIN can gain those privileges after `SET ROLE` into a separate privileged `NOLOGIN` group with direct or indirect SET option. Such a misgrant escaped the previous point-in-time check despite potential privileged database operations. [real PostgreSQL 17 RED CI 44954527922](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44954527922) verified five direct + two nested `SET ROLE`-reachable synthetic roles caused **7 genuine missing-denial failures / 166 earlier PG17 passes** without any role switch or privileged action. [ADR 0115](../adr/0115-arbitrary-privileged-role-membership-prelisten.md) / [issue #150](https://github.com/KeyserDSoze/TemporalMark/issues/150) add one read-only effective transitive catalog `pg_has_role(...,'MEMBER')` denial for any role with those five flags. The fix is not live production proof: no deployed Azure UAI, no SQL post-start drift blocking, no owner-level DDL restriction, no legally sealed evidence, no independently signed WebAuthn reviewer act. #128/#18/#14/#38/#50/#17/#13/#15 remain OPEN.


## Runtime direct SQL overgrant on reviewer decision token replay / registrar RP boundary (#151)

Prior #149 Entra prelisten protected V006 enrollment request and V012 unsigned challenge rows but omitted V010 owner-only `organization_reviewer_decision_proofs` (approval/rejection SHA256 proof replay ledger) and V013 `reviewer_registration_intents` plus `reviewer_registration_rp_policies` (unconsumable unsigned nonce, reviewer/registrar identity and owner-pinned RP/issuer/origin trust policy). Without checking these ACLs, a runtime login with an accidental **single-column** SELECT or UPDATE, table INSERT/DELETE/TRUNCATE/TRIGGER/REFERENCES could pass even with valid role-group membership. This is a hypothetical SQL misgrant, **not evidence an Azure account is compromised**, and the V015/V016 registrar SQL path remains SUSPENDED. [real PG17 RED CI 44956181715](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44956181715) real PG17 tests-only CI produced **27 missed-denial assertion failures / 173 earlier passes**. [ADR 0116](../adr/0116-reviewer-replay-registrar-rp-table-acl-prelisten.md)/[#151](https://github.com/KeyserDSoze/TemporalMark/issues/151) adds **21** read-only effective ACL denials to an already-authenticated, one-time API startup query; no role GRANT/REVOKE, migration or reviewer data is changed. Residual: post-start privilege drift, migration-owner bypass, signed independent human reviewer decision (#38), true registrar attestation (#50/#44), tenant invariants (#14), real Azure Entra #128/#18 and WORM/QTSP/eIDAS #17/#13/#15 all remain release blockers.


## V017 UNAPPROVED metadata-candidate tables and event ID sequence SQL overgrant (#152)

Earlier Entra PostgreSQL runtime prelisten denied direct privileges on enrollment, reviewer, quota and audit tables but did not inspect V017 owner-only `mds_unapproved_candidate_checkpoints`, `mds_unapproved_candidate_events` or their separate event IDENTITY sequence. A direct/column SQL runtime grant could read/write an **untrusted, UNAPPROVED FIDO MDS/CRL candidate** version/hash or history. A mistaken `USAGE/SELECT/UPDATE` grant on the identity sequence could expose or change its counter independently of any table grant. The immutable V017 already REVOKEs these from runtime groups; these tests address a hypothetical per-login privilege misconfiguration, **not evidence of deployed Azure compromise**. Real [real PostgreSQL 17 RED CI 44957628860](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44957628860) proved **21 unsafe missing-denial assertion failures / 200 prior PG17 passes**; [ADR 0117](../adr/0117-v017-owner-candidate-sequence-acl-prelisten.md) / [#152](https://github.com/KeyserDSoze/TemporalMark/issues/152) add 17 fixed read-only effective ACL checks in an already authenticated API SQL prelisten query only. Residual: post-start GRANT drift, SQL migration owner DDL/trigger bypass, restore/replay/equivocation or signed-witness custody (#61/#64), approved FIDO roots and CRLs (#57/#55), WebAuthn registrar human consent (#50/#38), actual Azure Entra SQL (#128/#18), WORM/certified QTSP/eIDAS (#17/#13/#15). None of these unresolved blocks are marked complete.


## Forgotten public SQL relation/sequence after future schema migration (#153)

Explicit static SQL privilege denies for V004–V020 can omit newly introduced owner-controlled tables, views and IDENTITY/ordinary sequences; they also previously omitted V004 `organization_provisioning_events` (initial admin and signed request proofs) and `public.schema_migrations` (SHA256 migration history). A direct/inherited/PUBLIC per-column SELECT or UPDATE GRANT to the ordinary API LOGIN could pass the explicit Entra candidate prelisten. Real [real PG17 RED CI 44960966724](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44960966724) proves **17 genuine missing-denial failures / 221 pre-existing successes** for these owner-only objects plus freshly created public TABLE, VIEW and SEQUENCE with a single test-only direct per-login grant each. [ADR 0118](../adr/0118-public-relation-privilege-inventory-prelisten.md) / [#153](https://github.com/KeyserDSoze/TemporalMark/issues/153) adds one read-only `pg_class` / `pg_namespace` **future-fail-closed** inventory, allowing runtime table ACLs only on four existing application data tables (with prior narrow positive/negative checks), no unexpected public relation data rights or public sequence rights. No real SQL misgrant is asserted; test objects/roles removed. Residual risk: after-boot GRANT drift, other namespaces, SQL owner DDL/ownership, impersonation, credential cache/actual Azure identity (#128/#18), reviewer/registrar human consent (#38/#50), cross-restore signed witness (#64/#61), WORM/eIDAS/QTSP (#17/#13/#15). Generic prelisten is not an independent custody or certification proof.


## SQL privilege escalation through unforeseen SECURITY DEFINER routine (#154)

The optional Entra-candidate API prelisten previously checked a finite list of sensitive function signatures, which can miss the **current V008 10-argument reviewer approval overload** and future owner-privileged functions/procedures. In PostgreSQL17 an independently authenticated runtime SQL LOGIN can gain execution of another owner's `SECURITY DEFINER` routine from a direct inherited grant, **or from the default PUBLIC EXECUTE privilege** on a newly created routine. An existing group-membership or table ACL screen does not capture that function privilege; trigger functions may be unusable directly yet a GRANT still violates least privilege. [real PostgreSQL 17 RED CI 44962732379](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44962732379) (after invalid test-fixture SQL quoting fixed in a tests-only commit) demonstrated **8 genuine missing-denial failures, 239 other successes** including normal SECURITY INVOKER acceptance in real PG17. [ADR 0119](../adr/0119-security-definer-function-execute-inventory-prelisten.md)/[#154](https://github.com/KeyserDSoze/TemporalMark/issues/154) add one fixed, read-only `pg_proc`/`pg_namespace` inventory deny for all effective non-system SECURITY DEFINER `function/procedure` EXECUTE except exactly V019 search quota routine OID. Retain all explicit named deny checks, role/tenant ACLs and normal API function use. Hypothetical SQL misgrant only—no actual Azure role violation or executed approval is proven. Residual: system schema privileges, post-start GRANT drift, SQL owner DDL/ALTER, live Azure SQL and Terraform password history (#128/#18), independently signed reviewer WebAuthn (#38/#50), witness rollback custody (#64/#61), WORM/eIDAS/QTSP (#17/#13/#15) all remain OPEN.


## Offline ZIP polyglot prefix/trailer ambiguity in unsigned period exports (#155)

Python's general-purpose `zipfile.ZipFile` intentionally accepts a ZIP preceded by a self-extracting-style binary prefix or followed by short unreferenced content. The pre-#155 TemporalMark offline checker verified all reported members and manifest/TSR SHA-256 but **did not bind the manifest to the exact physical ZIP container boundaries**: a valid v1 export plus opaque appended data still produced a success, despite a potential second interpretation/polyglot. Genuine [real Python RED 44966967378](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44966967378) independently proved **5 actual missing-denial cases / 24 passes** including CLI and NUL trailer, without changing token/member content. [ADR 0120](../adr/0120-offline-period-zip-strict-envelope.md)/[#155](https://github.com/KeyserDSoze/TemporalMark/issues/155) add a read-only, fixed-size strict v1 envelope check (first ZIP local header at offset zero; final 22-byte classic EOCD at physical EOF, single disk, zero comment, matching entries/central directory offset+size). It rejects prefix/suffix/ZIP64 or unreferenced central overlays before decompression and keeps all prior bounded ZIP/TSR/header/hash gates. Residual risk: coherent attacker modification of unsigned manifest+DER, missing records from an arbitrary-period export, colluding producer, no independent signed witness/key custody or WORM, no RFC3161 CMS/historical QTSP/EUTL verification or eIDAS qualification. Parent #17/#15/#13/#64/#61 remain OPEN.


## False qualified/incident status propagated from locally hash-consistent pilot registry (#156)

An owner-modified, corrupted-restored or otherwise invalid repository row can have valid organization, issue time, retained DER and matching SHA256 yet `validation_state` set to `VerifiedQualifiedExternal`/`VerifiedQualifiedOwn`/`VerifiedNonQualified`/`AffectedByIncident`. Before #156 the existing `TimestampRecord.Validate()` and registry read guards verified local bytes and tenant membership but returned such unsubstantiated states to Page/Search/Export or delivered a receipt without checking status. The offline ZIP verifier already rejected them; the API read path did not. Actual [real .NET Business TDD RED 44970125295](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44970125295) showed **16 genuine missing denials / 264 previous Business successes** with otherwise valid evidence. [ADR 0121](../adr/0121-pilot-registry-unsupported-validation-state-read-gate.md)/[#156](https://github.com/KeyserDSoze/TemporalMark/issues/156) add a minimal **`Unverified`-only pilot read gate** after original record hash validation, protecting list, SHA256 lookup (including lookahead), direct receipt and ZIP **before returning data**, not mutating SQL or reclassifying evidence. This is not proof of actual deployed fraud, signer trust, independent historical EUTL status, guaranteed SQL immutability, legal WORM or completeness. Qualified-status promotion, incident adjudication, SQL owner abuse, cross-snapshot metadata and full signed custody remain #15/#13/#17/#64/#61 open.


## Contradictory CRC/length values in local vs central ZIP metadata (#164)

The unqualified offline v1 ZIP checker could previously accept a deliberately contradictory **local-only** CRC32, compressed length or uncompressed length on `manifest.json` or a TSR, because Python `zipfile` trusts the central directory to read/CRC-check the unchanged data. The locally self-consistent manifest/TSR SHA256 did **not** establish consistent descriptions across ZIP structures. The current seekable .NET v1 producer writes CRC/length into each local header, so such disagreements and the bit-3 streaming descriptor layout are outside the approved v1 profile. Genuine [Python 3 GitHub RED 45005035684](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45005035684/attempts/1) demonstrated **eight actual missing-denial failures / 24 passing tests**, including six modified header DWORDs across manifest/token plus CLI and descriptor denial. [ADR 0122](../adr/0122-offline-v1-local-crc-and-size-directory-binding.md)/[#164](https://github.com/KeyserDSoze/TemporalMark/issues/164) now require fixed-header CRC32/compressed/uncompressed-size equality to central metadata and deny bit 3 before any decompression, without new I/O or data disclosure. This **does not prove** the archive is authentic, detect jointly rewritten unsigned DER+manifest or missing period entries, enforce immutable retention, validate CMS/RFC3161 or a historical QTSP/EUTL, or establish legal qualified timestamp status; #17/#15/#13/#61/#64 remain OPEN. Final GREEN on exact docs-inclusive main is a separate verification.


## Opaque bytes hidden between intact ZIP members and central directory (#165)

The unqualified v1 offline checker previously enforced a file-start local header, EOCD ending at physical EOF, matching local-vs-central method/flags/CRC/lengths and valid SHA256 of each receipt; however it did not verify that the **local compressed member regions were physically contiguous**. An opaque internal payload could be inserted between the original manifest and TSR, or after the last declared member and before the central directory, while appropriately adjusting ZIP offsets: Python `zipfile` then reads the *same intact* manifest and TSR, hashes/CRC pass, and the checker wrongly reports structurally consistent v1. This demonstrates a container ambiguity, **not an observed attack**, and is distinct from unrelated legal qualification or compromise of a signed token. Real tests-only [GitHub RED 45014471651](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45014471651/attempts/1) showed **four genuine missing-denial failures / 30 passing Python tests**, including redacted CLI, with valid ZIP fixtures. [ADR 0123](../adr/0123-offline-v1-zip-contiguous-local-member-layout.md)/[#165](https://github.com/KeyserDSoze/TemporalMark/issues/165) now calculate each member's header/name/extra/compressed-data interval using the existing fixed metadata read, requiring strict adjacency and exact final end-to-central binding **before any decompression**. Limitations remain: locally coherent forged unsigned manifest and DER, omitted records, missing independent signed WORM/high-water custody, RFC3161/CMS/EUTL historic validation and qualified legal status. Parent #17/#15/#13/#61/#64 and production #18 remain OPEN; current pilot still `Unverified`.


## Oversized uncompressed JSON hidden in a valid compressed pilot export ZIP (#166)

The .NET synchronous v1 ZIP exporter previously constrained retained raw DER count/bytes but allowed otherwise-valid repository metadata strings (especially `EvidenceReference`) to expand `manifest.json` arbitrarily. Deflate compression can produce a small outer archive even though the raw JSON **exceeds 8 MiB**, the maximum accepted by the standalone offline v1 checker. The API could thus return a self-produced ZIP that the independent verifier rejects, increasing memory/amplification risk and breaking interoperable evidence inspection. Unicode JSON escaping makes naive character-count budgets inaccurate. Real [TDD RED 45052741202](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45052741202/attempts/1): three *genuine* missing-denial Business failures with intact authorized DER+SHA, and successful large-in-budget case, 281 prior/other passes. [ADR 0124](../adr/0124-bounded-v1-manifest-and-zip-export-output.md) / [#166](https://github.com/KeyserDSoze/TemporalMark/issues/166) now require pre-ZIP bounded JSON serialization <=8 MiB, copying identical serialized bytes into ZIP and rejecting physical ZIP >80 MiB before any response; HTTP 413 remains generic. This is NOT a cryptographic, signed, independently witnessed or qualified completeness check. PostgreSQL row materialization, temporary serializer buffers, parallel-memory pressure, signed WORM/legal hold, historical QTSP/EUTL and actual certification remain OPEN #17/#15/#13/#64/#61/#18.


## API .NET ZIP and offline Python v1 validator drift (#167)

An authenticated real-tenant integration smoke already checks basic manifest and TSR contents returned by .NET `GET /api/v1/stamps/export` against disposable Keycloak/PG17 tenant canaries. Before #167 it used only Python's **permissive** `zipfile.ZipFile.read()` and never executed the strict offline v1 parser on those *actual API-produced bytes*. Meanwhile separate offline unit fixtures were generated by Python, so a producer regression could violate v1's header/size/contiguity gates without either separate test suite failing. A test-only stock-readable ZIP containing an opaque internal gap correctly returned original manifest+TSR, but the API smoke wrapper wrongly accepted it (real [GitHub RED 45053967169](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45053967169/attempts/1): 1 missing-denial / 1 positive pass, no fixture problem). [ADR 0125](../adr/0125-real-api-v1-offline-verifier-ci-bridge.md) and [#167](https://github.com/KeyserDSoze/TemporalMark/issues/167) now explicitly invoke the standalone verifier on every API ZIP in both tenant A/B and spoofed-selector smoke cases, before parsing; fail closed with generic privacy-preserving CI error, no disk artifact. No production logic, authorization, signed evidence or WORM changes. Cryptographic RFC3161, independently authenticated custody, completeness and qualification risks remain release-blocking #17/#15/#13/#61/#64/#18.


## Repository pagination overflow/order-contract integrity (#168)

A bug or dishonest alternate `ITimestampRegistry` implementation can return a tenant-owned, intact pilot `TimestampRecord` batch **larger than the caller's page `limit`** or in descending `IssuedUtc/id` order. Previous Business validators checked tenant, UTC, unique IDs, retained DER/SHA256 and `Unverified` but not page maximum or sorting. Search already checked max `limit+1` and all rows' digest/algorithm, yet a descending extra **lookahead** record could still drive misleading `hasMore`/pagination metadata. This is a data-contract flaw, **not** observed cross-tenant disclosure or an eIDAS cryptographic attack. Under [ADR 0126](../adr/0126-fail-closed-registry-page-and-imprint-search-order.md)/[#168](https://github.com/KeyserDSoze/TemporalMark/issues/168), service rejects oversized pages and unsorted full batches before metadata is returned; generic failures disclose no imprints/tenant/TSR. Genuine [TDD RED 45056357292](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45056357292/attempts/1) had **five missing-denial assertions / 285 passing Business tests**, with valid tenant/DER/hash/UTC fixtures. Minimal post-RED change [`216ae1b`](https://github.com/KeyserDSoze/TemporalMark/commit/216ae1b1257bbea7d2049dad3d4dd9b93800d3e8) neither reorders nor truncates invalid batches. Limits: no stable cross-page snapshot under concurrent writes, independently signed WORM custody, complete-period proof, CMS/TSU service verification or certified legal issuance. #14/#17/#15/#13/#61/#64/#18 remain OPEN.


## SHA-consistent oversized legacy DER via individual receipt GET (#169)

`TimestampRecord.Validate()` validates the SHA-256 of stored `ResponseDer` but **does not cap length**. The authenticated single-receipt `GET /api/v1/stamps/{id}/receipt` previously returned arbitrarily large, internally self-consistent historical/compromised database `bytea` rows after tenant scope, even though synchronous ZIP export and standalone offline v1 checker cap individual receipts at 1 MiB. A tenant-admin read could amplify per-request output and a successful-download audit would be prepared for unsupported pilot evidence. It is an observed **pilot resource-policy gap**, not cryptographic RFC3161 forgery, cross-tenant disclosure or proof of qualified evidence.

[ADR 0127](../adr/0127-pilot-single-receipt-download-der-byte-bound.md) / [#169](https://github.com/KeyserDSoze/TemporalMark/issues/169): Business denies retained DER beyond 1 MiB after tenant equality **before SHA-256**, throwing a generic typed error; API only maps this exact error to 409/no-store and does not append a `ReceiptDownloadPrepared` audit for a denied download. SHA-consistent source DER exactly 1 MiB remains readable. Test-only [RED 45059617454](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45059617454/attempts/1) verified one missing-denial assertion / 292 passing Business tests, then production changes [`1efb3d1`](https://github.com/KeyserDSoze/TemporalMark/commit/1efb3d112b11887d09d5e5a3006d88d6d7781138) and [`ff6dbf5`](https://github.com/KeyserDSoze/TemporalMark/commit/ff6dbf5017dd0e28c146b8b7770850dadca8279a). Real signed-Keycloak/PG17 A 409 / B 404 / no audit fixture added to Docker smoke. **Residual:** `bytea` is already materialized by Npgsql before the guard; there is no per-user concurrent memory quota or legal WORM/EUTL verification, and genuine future QTSP tokens may require revisiting pilot size thresholds under external assessment. #17/#15/#13/#61/#64/#18 remain OPEN.


## Same-tenant wrong-receipt-ID substitution at Business read boundary (#170)

The actual PostgreSQL registry adapter performs a parameterized `WHERE organization_id=@org AND id=@id`, but the shared Business `DownloadReceiptAsync` previously accepted a **correct-tenant** `TimestampRecord` whose `Id` differed from requested receipt ID. A buggy repository adapter or incorrect data mapper could therefore cause successful delivery of **different DER** with a valid local SHA256, while the `ReceiptDownloadPrepared` event referred to the *caller-requested* ID; a serious evidence-provenance confusion even without cross-tenant access. After ADR-first [ADR 0128](../adr/0128-verify-returned-receipt-identity-before-delivery.md) / [#170](https://github.com/KeyserDSoze/TemporalMark/issues/170), a fixed-message fail-closed ID equality guard runs after existing tenant check, before size and DER hash validation and before any audit. Genuine tests-only [RED 45063752182](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45063752182/attempts/1): 293 passes/2 missing identity-denial failures, including wrong ID with oversized hash-correct payload. Minimal [source `5e643d7`](https://github.com/KeyserDSoze/TemporalMark/commit/5e643d725a75419f85d0375234358e845a920b89) keeps Postgres/API/authorization unchanged.

Residual: no proof of qualified issuer signature, actual issuance, immutable WORM record, cross-page complete period, independent audit witness, trustworthy historical QTSP/EUTL status, or protection against a fully compromised DB owner rewriting data. #17/#15/#13/#61/#64/#18 remain OPEN.


## Oversized retained DER hashing via metadata-only page and imprint-search read (#171)

The PostgreSQL registry currently materializes full `ResponseDer` even on authenticated tenant-admin list and exact SHA-256 document-imprint search routes that return only safe JSON metadata. Before #171, shared `ValidateReturnedRecords` hashed every returned DER with `TimestampRecord.Validate()` but **did not check** the existing 1MiB-per-token and 64MiB-total pilot budgets used by synchronous ZIP. A self-consistent malicious/legacy oversized row, or a 200-row page of valid 1MiB receipts, could exceed the intended CPU/read budget and disclose metadata for receipts that single-receipt and ZIP endpoints refused. Search's `limit + 1` lookahead was also vulnerable.

[ADR 0129](../adr/0129-bounded-page-and-search-der-before-hashing.md)/[#171](https://github.com/KeyserDSoze/TemporalMark/issues/171): all returned tenant/period scopes are checked first, then the complete batch gets 1MiB-per-receipt and 64MiB-cumulative prehash admission; oversized rows or batches yield a generic no-values `InvalidOperationException` before metadata or `hasMore`. All prior checks remain. Real tests-only [RED 45066373120](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45066373120/attempts/1) failed three exact missing-denial assertions (298 Business tests passed); Business change followed [`6bc8c1a`](https://github.com/KeyserDSoze/TemporalMark/commit/6bc8c1a73c2deacdeaaabdb0262f9150d705dde1). Disposable Keycloak/PG17 CI now probes real A-page refusal with A-only oversized canary and B-page unaffected. The guard is **after Npgsql materialization**, so cannot prevent prehash allocation/transfer, malicious concurrent requests or SQL query amplification; it does not establish a cryptographic timestamp or signed custody. No production eIDAS/CAB status, GDPR retention approval, HSM trust or WORM claim. #17/#15/#13/#61/#64/#18 remain OPEN.


## PostgreSQL pre-wire DER projection on tenant registry metadata reads (#172)

Scoped child [#172](https://github.com/KeyserDSoze/TemporalMark/issues/172) follows #171's **postmaterialization** read/CPU guard. Prior PostgreSQL `SELECT response_der` on tenant list and imprint-search sent complete potentially massive legacy `bytea` values to Npgsql even though HTTP returned only metadata; an admin could cause unnecessary per-request network/memory consumption before a 1MiB-per-row or 64MiB aggregate rejection. [ADR 0130](../adr/0130-snapshot-bound-postgres-registry-der-projection.md) now limits **wire-projected DER** using one tenant/UTC/imprint-constrained PostgreSQL statement and single MVCC snapshot: materialized ID+logical-length CTE, all-rows windowed length admission, and `CASE` server-side `NULL::bytea` whenever **any** chosen row or full batch is oversized, including lookahead. The provider checks `IsDBNull(9)` before reading `byte[]` and fails closed with a constant non-sensitive error; original Business SHA256 checks all accepted DER. Existing ZIP 413 and GET receipt 409 unchanged, no SQL migrations or extra privileges. Source RED-first [PG17 Actions 45070013421](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45070013421/attempts/1): three missing-denial failures out of 251/248 passes; post-RED [`198e855`](https://github.com/KeyserDSoze/TemporalMark/commit/198e855364e0eabf01a88ba93edb3fb904d3529e).

**Remaining threats:** no demonstrated total elimination of server TOAST/page/sort reads, no database CPU/query timing/burst quotas, no protection from excessive *concurrent* allowed 64MiB batches or a database owner rewriting evidence or SQL; schema changes/SQL plan regressions should trigger repeated real PostgreSQL profiling before production. No complete period/WORM/independent signed custody, GDPR retention, certified long-term verifier, qualified QTSP or CAB release claim. #17/#15/#13/#61/#64/#18/#38/#50 remain OPEN.


## Pre-wire PostgreSQL period-export DER resource bounds (#173)

The audited synchronous ZIP export previously enforced **10k rows / 1MiB DER / 64MiB total source DER** only after `PostgresTimestampRegistry.ForExportAsync` fully materialized `SELECT response_der` for up to 10,001 rows. A SHA-consistent oversized legacy row, valid 65MiB batch, or 10001 tiny rows could consume PostgreSQL result-wire and Npgsql memory before an eventual HTTP 413. This is a bounded pilot availability/resource weakness, **not proof of an exploit, integrity compromise or qualified timestamp incident**.

[ADR 0131](../adr/0131-prewire-postgres-period-export-der-budgets.md) / [issue #173](https://github.com/KeyserDSoze/TemporalMark/issues/173) extend the preceding #172 same-statement MVCC approach **only to `ForExportAsync`**, with different typed error: materialized ID/byte-length selection, full-batch windowed `bool_and/sum/count`, all-or-none SQL `CASE ... ELSE NULL::bytea`. A failed budget prevents raw DER projection over the PG/Npgsql wire and causes existing `ExportTooLargeException` **before** `GetFieldValue<byte[]>`, so the API still responds HTTP 413 before writing any `period_export_prepared`. Business preserves local original-DER SHA256/tenant/period/Unverified/audit checks. Tests-only real PG17 [RED 45074007385](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45074007385/attempts/1): **three precise missing-denial failures / 253 passing** of 256; after-RED source [`2eda374`](https://github.com/KeyserDSoze/TemporalMark/commit/2eda3746ee24225c426d0bea237621ccf1baa129). Added real signed-Keycloak tenant A ZIP 413/no audit delta, B original ZIP 200.

Residual risks: still materializes accepted <=64MiB raw source and in-memory ZIP, no per-actor export quota or global concurrency admission, PostgreSQL TOAST reads and sort CPU not strictly capped, no guaranteed full-period/multi-part export coverage, no WORM/legal hold/independent signature/custody or historic QTSP/CMS validation. Original `FindByIdAsync` still fetches whole legacy DER before its own 1MiB GET 409; this must be separately tracked. #17/#15/#13/#61/#64/#18/#38/#50 stay OPEN. No certified eIDAS/QTSP claims.


## Oversized individual receipt read before PostgreSQL wire projection (#174)

Before #174, `TimestampRegistryService.DownloadReceiptAsync` and the API already refused SHA-consistent legacy DER >1MiB after tenant/ID authorization (409/no-store, no receipt-prepared audit). The real `PostgresTimestampRegistry.FindByIdAsync` nevertheless selected the **full `bytea`** and Npgsql materialized it *before* this Business check, permitting needless network/memory pressure on an authenticated own-tenant GET. This is a per-read pilot resource vulnerability, **not observed tenant disclosure or a cryptographic timestamp attack**.

[ADR 0132](../adr/0132-single-receipt-postgres-prewire-der-guard.md) and [#174](https://github.com/KeyserDSoze/TemporalMark/issues/174) change only the parameterized `WHERE organization_id=@org AND id=@id` PostgreSQL **one-statement** row projection: `octet_length(response_der)` gate at the pilot 1MiB threshold, raw `response_der` only if accepted, otherwise `NULL::bytea`. The provider sees the NULL for an authorized row and throws the same generic `ReceiptTooLargeException` **before reading a managed byte array**. A missing/foreign row never passes the WHERE filter and stays null/HTTP404, including when foreign evidence is oversized; valid original DER stays 200 plus one successful receipt-prepared audit. The preexisting Business independent SHA256/tenant/exact-ID/status checks and API 409/no-store before audit remain. Test-only real PG17 [RED 45127882882](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45127882882/attempts/1) showed **257/259 pass and exactly two missing-denial failures**; code changed only after RED [`4bc6780`](https://github.com/KeyserDSoze/TemporalMark/commit/4bc67806309e4c96f045ec57fdbb594ce4bd3d08).

**Residual:** PostgreSQL may still access internal TOAST storage/metadata; other 64MiB accepted batches and concurrent requests remain outside this bound. No legal WORM object lock, signed independent custody/audit, complete-period export, historical QTSP/eIDAS status, CAB release, SQL owner-compromise protection or qualified timestamp claim. Parent #17/#15/#13/#61/#64/#18/#38/#50 stay OPEN.
