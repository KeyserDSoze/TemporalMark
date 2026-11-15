# Controlled OIDC organization enrollment (pilot)

**Only a restricted operator executable, not an HTTP self-registration feature.** Read [ADR 0007](../adr/0007-oidc-operator-provisioning.md), [ADR 0006](../adr/0006-tenant-bootstrap-and-admin-integrity.md) and #23 before using.

## Prerequisites
- Trusted OIDC discovery endpoint with valid signed keys (HTTPS; local Keycloak loopback HTTP only for an explicit development run).
- Independent authentication to the SAME issuer for two DISTINCT people:
  (1) platform operator with signed `platform_provisioner` role, audience `temporalmark-provisioner`; (2) intended first tenant admin with signed `tenant_admin` role, audience `temporalmark-api`.
- Fresh, non-replayed OIDC access tokens (`iat` within 5 minutes), with audience, issuer, `sub`, signature and expiry. Supported roles: direct `role` or `roles` claims.
- Database migrated to `V008`, with a dedicated `temporalmark_provisioner` SQL login assigned only to `temporalmark_provisioner_group`. Runtime API credential must be separate and cannot EXECUTE privileged bootstrap routines.
- A **mandatory live Keycloak token introspection client** (RFC 7662) with confidential credentials held outside the token files, to verify both access tokens are still active. This adapter supports Keycloak, not Microsoft Entra; other providers fail closed until an implementation is added.
- Controlled review/approval of legal organization name and initial admin identity. The CLI now requires a distinct `platform_approver` and DB approval, but does **not** prove independent human consent, MFA step-up or current directory role status.

## Explicit three-phase approval workflow (#29)

The existing immediate-enrollment CLI has been replaced by a short-lived, DB-enforced **request / approve / complete** flow (ADR 0009). Use an approved request review/consent process; these shell examples show syntax, **not** proof of an actual human independent review.

Preconditions: `V006` and `V007` applied; three different authenticated persons with signed and **live** OIDC access tokens: `platform_provisioner`, `tenant_admin`, `platform_approver`. Keep each token in a separately protected owner-only file (`0600`, never argv/logs). Do not deploy the seeded password-grant Keycloak test fixture outside local CI.

```sh
umask 077
export PROVISIONING_OIDC_ISSUER='https://identity.example.org/realm'
export PROVISIONING_LIVE_PROVIDER='keycloak'
export PROVISIONING_INTROSPECTION_CLIENT_ID='<approved-confidential-client>'
export PROVISIONING_INTROSPECTION_CLIENT_SECRET='<read-from-approved-vault>'
export PROVISIONING_DIRECTORY_CLIENT_ID='<dedicated-directory-readonly-client>'
export PROVISIONING_DIRECTORY_CLIENT_SECRET='<read-from-approved-vault>'
export PROVISIONING_OPERATOR_AUDIENCE='temporalmark-provisioner'
export PROVISIONING_ADMIN_AUDIENCE='temporalmark-api'
export PROVISIONING_APPROVER_AUDIENCE='temporalmark-approval'
# Production: pin an ACR proven to be bound to an MFA/step-up Keycloak browser flow.
# The string itself is NOT proof of MFA.
export PROVISIONING_APPROVER_REQUIRED_ACR='urn:temporalmark:loa:2'
# These connection strings must be read from the approved operator secret vault.
export TEMPORALMARK_PROVISIONING_DB='<restricted-operator-SQL-login>'
export TEMPORALMARK_APPROVER_DB='<independent-approver-SQL-login>'

# 1. Operator requests a tenant, but cannot activate it.
dotnet run --project src/backend/applications/TemporalMark.Provisioner -- \
  request --organization-name 'Approved Customer Name' \
  --operator-token-file /restricted/operator.jwt \
  --first-admin-token-file /restricted/initial-admin.jwt
# Output: Approval requested: <organization/request UUID>

# 2. Separately authenticated reviewer reads the ORIGINAL record from SQL,
# not a name or identity supplied by the operator.
dotnet run --project src/backend/applications/TemporalMark.Provisioner -- \
  review --request-id '<UUID-from-step-1>' \
  --approver-token-file /restricted/approver.jwt
# Check the returned organization, issuer, subjects, expiry, and Review SHA-256
# against an independently approved real-world source.

# 3. After independent scrutiny, confirm the exact review SHA-256.
dotnet run --project src/backend/applications/TemporalMark.Provisioner -- \
  approve --request-id '<UUID-from-step-1>' \
  --review-sha256 '<64-uppercase-hex-from-review>' \
  --approver-token-file /restricted/approver.jwt

# 4. Operator presents currently valid, live tokens again and consumes approval.
dotnet run --project src/backend/applications/TemporalMark.Provisioner -- \
  complete --request-id '<UUID-from-step-1>' \
  --organization-name 'Approved Customer Name' \
  --operator-token-file /restricted/operator.jwt \
  --first-admin-token-file /restricted/initial-admin.jwt
# Output: Organization created: <same UUID>
```

The pending request expires exactly **five minutes** after it was created in the pilot. Rejected, incomplete, expired or mismatched approvals cannot produce a tenant; used approvals cannot be reused. PostgreSQL enforces different subjects and isolated SQL roles, and the completion transaction also links the pilot audit record to the approval. **The CLI does not provide an independent request-review UI, demonstrated MFA step-up, legally sealed audit, or accredited approval process. Current directory role checks are provided under ADR 0010.** Complete operator-guided provisioning policy under issue #27 and #25.

A separate IdP administrator must still map the newly created `organization_id` to the first admin. Check signed claims and `GET /api/v1/me`; automated invitations and multi-org selection remain #14.

## Mandatory live token-status checks (#26)
The operator CLI checks each signed access token again through the trusted Keycloak RFC 7662 introspection endpoint **immediately before creating the organization**. The confidential client must be a permitted audience (`aud`) of both operator and first-admin tokens, especially on Keycloak 26.4.12+; do not enable compatibility relaxations. A returned `active=false`, mismatched issuer/subject/audience/role, unreachable IdP or missing credentials prevents any DB write. This is **not** an active-user directory/role lookup, human approval or an atomic cross-system revocation guarantee. See [ADR 0008](../adr/0008-live-keycloak-introspection.md) and issue #25. The local realm has a fake client secret for CI only; **never reuse the secret or the password-grant fixture in production**.

## Mandatory current-account and effective-role checks (#30)

The CLI additionally obtains a distinct, short-lived service-account bearer token from the **same pinned Keycloak realm** and queries the account status plus *current effective realm roles* through the Keycloak Admin REST API, separately from JWT/introspection. Every request, approval and completion performs fresh checks for the intended user(s). The dedicated confidential directory client must be granted only the required **read-only** `realm-management` permissions (`view-users`, `view-realm`, optionally `query-users` according to approved Keycloak configuration); no `realm-admin` or `manage-users`. An unavailable directory, missing role, disabled user, wrong ID/issuer, expired/invalid service credential or HTTP failure blocks all provisioning actions. Do **not** reuse the development service account, its demo secret, or the test setup script in production. The Keycloak directory check is independent of token claims but not a signed assertion; MFA, actual human signoff, policy attestation and TOCTOU reconciliation remain outstanding. See [ADR 0010](../adr/0010-keycloak-current-directory-check.md) and #27/#25.

## Signed approver authentication freshness and ACR (#32)

The approval executable now **requires** `PROVISIONING_APPROVER_REQUIRED_ACR`. This exact value must be validated and signed by the trusted IdP as part of a tested policy mapping to a *real* MFA/step-up authentication flow; a non-empty ACR field is insufficient evidence that MFA happened. Its `auth_time` must be numeric and no older than 120 seconds, and must agree with signed token `iat`. Missing/weak/stale claims fail closed. Keycloak's step-up configuration uses ACR→LoA mapping with a browser authentication flow that can require password plus OTP or WebAuthn; administrators must validate that configuration **before real onboarding**. See [ADR 0011](../adr/0011-signed-approval-authentication-assurance.md) and #31.

**Disposable CI exception (not MFA):** `tests/integration/provisioning-smoke.sh` uses `PROVISIONING_DEVELOPMENT_PASSWORD_GRANT_NO_MFA=true`, only with the exact loopback issuer `http://localhost:8081/realms/temporalmark` and fixed test approver UUID. This retains historical approval/replay/revocation tests but does not exercise MFA. No other issuer, approver or production environment can use this exception. Never copy its configuration into an installation guide, infrastructure secrets or a production deployment. #31 remains OPEN until genuine interactive MFA and independently reviewed consent are demonstrated.

## Verified approval provenance (#33)

Migration V008 records the authentication **classification** (not raw JWT): `OIDC_ACR_ASSERTED`, `DISPOSABLE_PASSWORD_ONLY` for the exact disposable CI account, or historical-only `LEGACY_UNVERIFIED`, together with bounded `acr`, verified `auth_time`, and a policy identifier when applicable. The earlier seven-argument SQL approval function is not executable by the approver role. A previously approved-but-unconsumed legacy request cannot create an organization; repeat approval using the new controlled workflow. A signed ACR still **does not certify real MFA**, and a local password-grant approval **is explicitly NOT MFA**. See [ADR 0012](../adr/0012-approval-assurance-provenance.md). #31 remains OPEN for real browser OTP/WebAuthn and independent human consent.

## Real browser OTP + PKCE regression (CI only, #34)

The local Compose stack now imports a **separate** `temporalmark-mfa-ci` test realm. The Playwright `mfa.config.ts` / `mfa.spec.ts` suite uses OIDC Authorization Code and PKCE S256 with a required authentication context, explicitly configured Keycloak LoA1 username/password and LoA2 **OTP**. It first enrolls an OTP credential and discards the setup login (enrollment is **not** evidence of MFA), then uses a separate browser session to show that the password alone does not issue an access token, an incorrect OTP is refused, and a correct TOTP is required. It verifies the actual Keycloak-signed LoA2 token and passes that token to the **strict .NET** signature/ACR policy check without using the password-grant exception. Keycloak's one-time OTP reuse rule remains enabled; the test waits for a fresh 30-second interval after enrollment.

Run this **only** inside disposable Docker/Keycloak CI via the `docker-smoke` job. All test accounts/secrets and optional HTTP localhost are development fixtures; the token is stored briefly as a restricted 0600 temp file and removed before job exit; browser tracing/screenshots/video are disabled. The automated TOTP generator holds the enrollment secret and **does not prove independent human or separate-device control**. It is also not the reviewer-facing approval workflow; #31 stays OPEN for actual independently witnessed consent, production Keycloak MFA governance, protected signing and WORM evidence. See [ADR 0013](../adr/0013-disposable-keycloak-real-otp-pkce.md).

## Approver-only original database view (V009; #36)

The new `review` command shows server-fetched original scope after signed OIDC + live token + current directory-role + ACR authentication. Its digest binds UUID, name, issuer, both subjects and exact expiration. `approve` requires `--review-sha256` and no longer accepts manually copied name and subject flags. Missing, expired, consumed and altered records or wrong digest are refused before SQL approval. This is *not a human-held digital signature* or explicit binding of a real reviewer's act to a hardware authenticator; #35 remains OPEN. See [ADR 0014](../adr/0014-db-backed-approval-review.md).

## Explicit reviewer rejection (V010, #37)

After independently retrieving the original scope with the approved `review` command, the **same separately authenticated reviewer** can choose to deny the request. Use only an allowlisted reason code; never place secret or freeform personal data in a command argument:

```sh
dotnet run --project src/backend/applications/TemporalMark.Provisioner -- \
  reject --request-id '<UUID-from-review>' \
  --review-sha256 '<uppercase-64-character-digest-shown-by-review>' \
  --reason-code UNVERIFIED_IDENTITY \
  --approver-token-file /restricted/approver.jwt
# Output: Enrollment rejected: <same UUID>
```

Allowed reasons: `UNVERIFIED_ORGANIZATION`, `UNVERIFIED_IDENTITY`, `SCOPE_MISMATCH`, `POLICY_DENIED`. Rejection is **terminal** and cannot be approved, reviewed again or completed; the organization is not created. The database stores the reviewer subject, UTC decision timestamp, canonical review digest, SHA-256 fingerprint of the short-lived OIDC token, and reason code; a unique registry prevents use of that token for another approval OR rejection. Strong signed JWT, live account/current role and ACR checks are mandatory before the protected CLI asks PostgreSQL to reject. The local password-grant CI exception is explicitly **NON_MFA**. The digest is not a signed human decision, and the SQL approver credential remains a security-critical trust boundary. See [ADR 0015](../adr/0015-terminal-rejection-and-token-proof-replay.md); independently signed human consent remains #35.

## Issue #39: server-issued reviewer challenge (unsigned prerequisite)

After checking the original database review with `review`, an authenticated third-party approver can request exactly one cryptographic nonce for a pending enrollment:

```sh
dotnet run --project src/backend/applications/TemporalMark.Provisioner -- \
  challenge --request-id '<UUID>' --review-sha256 '<64-UPPERCASE-HEX>' \
  --decision APPROVE --reason-code NONE \
  --approver-token-file /restricted/approver.jwt
# For a REJECT intent, use --decision REJECT --reason-code POLICY_DENIED
```

The database checks the original legal organization, issuer, operator and first-admin subjects and **recomputes the canonical hash itself**. Its 48-byte challenge (three v4 UUIDs, ~366 random bits) expires within 60 seconds and no later than the original request, and may not be reissued. This CLI issues an **UNSIGNED CHALLENGE ONLY**. No signature is accepted, no approval/rejection is made, and the existing reviewer SQL credentials still permit the older pilot decisions. This is not a certified, human-held WebAuthn signature or legal evidence. See [ADR 0016](../adr/0016-server-issued-reviewer-challenge.md); real signature/DB privilege cutover is #38.

## Future WebAuthn reviewer origin configuration (ADR 0017; #40)

The new `ReviewerWebAuthnRelyingPartyPolicy` is **validation-only**; it is not connected to reviewer CLI, Keycloak, a browser or SQL. There are no production `WEBAUTHN_*` configuration keys or registration/assertion endpoints. Future operators must approve an exact HTTPS FQDN and pin RP ID equal to the host, including the non-default HTTPS port when applicable. Never trust an unvalidated forwarded host/browser origin as configuration. On-prem private IP or localhost is not accepted; Azure must pin an independently approved custom review origin. See [RP deployment checklist](WEBAUTHN_RP_POLICY.md) and [ADR 0017](../adr/0017-pinned-webauthn-rp-origin-policy.md). Issuing the V012 challenge is not authorization or an independent signer: reviewer-held credential enrollment, signature verification, human review, SQL consumption/grant cutover and WORM legal evidence remain open under #38/#35/#31/#17.

## Non-authorizing WebAuthn client-data preflight (ADR 0018; #41)

A bounded pure .NET `ReviewerWebAuthnClientDataPolicy` now checks *untrusted* browser `clientDataJSON` for `webauthn.get`, original V012 48-byte nonce (canonical base64url), server-pinned HTTPS origin and top-level same-origin context. This class is **not connected** to the CLI or an HTTP endpoint and cannot approve/reject or consume a challenge. It intentionally does NOT verify an authenticator signature, registered credential, UV, RP hash or user consent. No WebAuthn production runtime variables are available. The current approver SQL login still has the historical direct approval/rejection capability; deploy none of these as a real four-eyes gate. See [ADR 0018](../adr/0018-webauthn-clientdata-preflight.md) and [operator guidelines](WEBAUTHN_CLIENT_DATA.md). Keep #38, #35/#31, WORM #17 and qualification #13 open.

## WebAuthn authenticatorData structural preflight (ADR 0019; #42)

A further validation-only `ReviewerWebAuthnAuthenticatorDataPolicy` parses 37-byte basic assertion data, comparing SHA-256 of the pinned RP ID and checking UP+UV, reserved/unsupported flags, legal backup combinations and unsigned big-endian `signCount`. **A malicious browser can forge all these bytes.** The parser is not connected to the provisioning CLI/Keycloak/API or SQL and **does not** verify a registered reviewer-held signature, authorize a human decision, consume a challenge or update a credential counter. For on-prem/Azure operations, do not install/enable a WebAuthn assertion endpoint or invent `WEBAUTHN_*` settings: the real verifier, key enrollment, current-role checks, atomically consumed signed decision and revocation of old reviewer SQL routine grants are still required under #38. See [ADR 0019](../adr/0019-webauthn-authenticator-data-preflight.md) and [operator guide](WEBAUTHN_AUTHENTICATOR_DATA.md).

## Exact WebAuthn signing-message bytes (non-authorizing, ADR 0020; #43)

A .NET 10 pure helper now builds `original 37-byte authenticatorData || SHA256(original clientDataJSON)` after the strict existing two **untrusted** preflight gates. It returns **an untrusted raw message**, NOT a signature or a verified reviewer. The client can forge both arrays, and there is no public or CLI verifier, approved credential store, trusted human consent, one-use signed SQL transaction or automatic credential recovery. **Do not use the resulting bytes to authorize APPROVE/REJECT.** The existing approver SQL role retains old direct decision EXECUTE until the real verified WebAuthn gate and a reviewed privilege cutover under #38. On-prem/Azure must first approve exact HTTPS RP/origin, independently register trusted reviewers and deploy an audited maintained verifier with signed assertions bound to the original V012 nonce and scope. See [ADR 0020](../adr/0020-webauthn-unsigned-signing-transcript.md) and [operator guide](WEBAUTHN_TRANSCRIPT.md). The Fido2 .NET library is a future evaluated candidate, **not installed or operational**.

## Registrar-only V013 registration intent (ADR 0021, #45)

V013 adds only a **non-consumable, untrusted intent** for eventual reviewer WebAuthn credential creation: the migration-owner pins an exact HTTPS identity issuer/RP hostname/origin under a documented change ticket, and a separate **NOLOGIN registrar role without members or a seeded login** alone receives EXECUTE on the nonce-issuance function. The existing reviewer/approver/provisioner/runtime SQL roles cannot mint or read intents. No current JWT/Keycloak/Entra validator is connected to this new SQL function, so plain caller subject strings are NOT independently authenticated humans; no true credential can be registered, approved or used. **Do not grant registrar role membership as a production shortcut or expose issuance as HTTP.** See [ADR 0021](../adr/0021-registrar-only-unconsumable-credential-intent.md) and [pinning/runbook](WEBAUTHN_REGISTRAR_INTENT.md). A real independently signed registrar approval, verified WebAuthn `create()` attestation and registered-key verification remain #44, while the old direct unsigned approval SQL routine cutover remains #38. No WORM/QTSP qualification.

## Registrar OIDC two-person preflight (ADR 0022; #47)

An isolated .NET 10 `ReviewerCredentialRegistrarIdentityGate` now **checks** two different independently signed OIDC principals: exact pinned HTTPS issuer, separate registrar/reviewer audiences and `platform_credential_registrar`/`platform_approver` roles, BOTH with fresh ACR+`auth_time` (no password-grant exception), RFC7662 live token state and current Keycloak account/effective realm roles. It can exclude original SQL-fetched operator/admin actors. It is **NOT connected** to this CLI or SQL, no new issuer/role credentials/configuration is provisioned, and no registration or tenant decision is authorized. Do not grant `temporalmark_credential_registrar_group` membership or add a new service login to shortcut independent human verification. The Keycloak CI signing keys are synthetic and the dedicated real registrar MFA browser login is **not** demonstrated yet. See [ADR 0022](../adr/0022-registrar-dual-oidc-identity-preflight.md), [security guidance](WEBAUTHN_REGISTRAR_IDENTITY.md). #46/#44/#38 remain OPEN; WORM/QTSP #17/#13 unchanged.

## CI-only real registrar MFA and current-role checks (ADR 0023; #48)

The disposable Keycloak `temporalmark-mfa-ci` realm adds a **distinct** registrar `platform_credential_registrar` role, an independent registrar OIDC audience, fresh browser TOTP+PKCE login and a second actual signed token alongside the reviewer. .NET reuses the production signed JWT / RFC7662 / current directory adapters and #47 dual-identity gate, and the same registrar JWT is denied after effective role removal or account disablement. **No production registrar role/audience/client is provisioned.** A local HTTP option is available only for the hardcoded disposable MFA realm and is explicitly disabled by default. Never enable the disposable master admin/client credentials or CI OTP subjects in production. There is **no** registrar SQL login/group membership or V013 issuance from this code, no WebAuthn attestation, no registered key, no human signed decision and no legal WORM evidence. See [ADR 0023](../adr/0023-disposable-keycloak-registrar-browser-mfa.md) and [CI guide](KEYCLOAK_REGISTRAR_MFA_CI.md). #46/#44/#38 stay OPEN.

## Separate registrar-intent CLI (ADR 0024, #49)

A standalone command `TemporalMark.Provisioner registrar-intent --registrar-token-file PATH --reviewer-token-file PATH` now bridges two freshly signed+live/current enabled Keycloak user identities to one **UNCONSUMABLE registration nonce** after strict HTTPS issuer, approved reviewer subject and RP/origin pinning. It is NOT reachable from API/PWA, accepts no client-selected RP/issuer/signer arguments, and does NOT reuse old provisioner/approver DB logins or the disposable password-only/no-MFA exception. The PostgreSQL adapter requires a separately provisioned **restricted registrar SQL LOGIN** and checks actual session_user/current_user, registrar NOLOGIN group membership and no table rights. **No registrar login or membership is installed by migrations or local Docker**; see [runbook](REGISTRAR_SQL_INTENT.md) for mandatory independent CAB approval, Keycloak true MFA flow, vault/host isolation and recovery. No WebAuthn key or signature is verified or activated; V013 intents expire, cannot be consumed or reissued, and a stolen login can bypass the OIDC CLI unless independently isolated. #46, #44, #38, #17/#13 stay OPEN.
