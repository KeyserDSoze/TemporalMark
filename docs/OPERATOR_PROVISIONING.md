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
