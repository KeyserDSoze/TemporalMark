# Controlled OIDC organization enrollment (pilot)

**Only a restricted operator executable, not an HTTP self-registration feature.** Read [ADR 0007](../adr/0007-oidc-operator-provisioning.md), [ADR 0006](../adr/0006-tenant-bootstrap-and-admin-integrity.md) and #23 before using.

## Prerequisites
- Trusted OIDC discovery endpoint with valid signed keys (HTTPS; local Keycloak loopback HTTP only for an explicit development run).
- Independent authentication to the SAME issuer for two DISTINCT people:
  (1) platform operator with signed `platform_provisioner` role, audience `temporalmark-provisioner`; (2) intended first tenant admin with signed `tenant_admin` role, audience `temporalmark-api`.
- Fresh, non-replayed OIDC access tokens (`iat` within 5 minutes), with audience, issuer, `sub`, signature and expiry. Supported roles: direct `role` or `roles` claims.
- Database migrated to `V005`, with a dedicated `temporalmark_provisioner` SQL login assigned only to `temporalmark_provisioner_group`. Runtime API credential must be separate and cannot EXECUTE privileged bootstrap routines.
- A **mandatory live Keycloak token introspection client** (RFC 7662) with confidential credentials held outside the token files, to verify both access tokens are still active. This adapter supports Keycloak, not Microsoft Entra; other providers fail closed until an implementation is added.
- Controlled review/approval of legal organization name and initial admin identity. The CLI still does not enforce two-person approval, MFA step-up or an independent fresh role/locked-account lookup.

## Execute the command (non-production reference)
Acquire each access token through the organization's approved secure OIDC process (in production: interactive OIDC PKCE/device and approved user roles). Store the token strings as two separate files, with permissions `0600` and no extra content:
```sh
umask 077
# The two files must be obtained through independent signed OIDC login flows.
# Do not paste tokens into shell command arguments, logs or Git.
export PROVISIONING_OIDC_ISSUER='https://identity.example.org/realm'
export PROVISIONING_LIVE_PROVIDER='keycloak'
export PROVISIONING_INTROSPECTION_CLIENT_ID='dedicated-confidential-client'
export PROVISIONING_INTROSPECTION_CLIENT_SECRET='<retrieve-from-secret-vault>'
export PROVISIONING_OPERATOR_AUDIENCE='temporalmark-provisioner'
export PROVISIONING_ADMIN_AUDIENCE='temporalmark-api'
export TEMPORALMARK_PROVISIONING_DB='<secure secret from authorized operator vault>'
dotnet run --project src/backend/applications/TemporalMark.Provisioner \
  -- --organization-name 'Approved Customer Name' \
     --operator-token-file /restricted/operator.jwt \
     --first-admin-token-file /restricted/initial-admin.jwt
```
The executable derives both subjects **only** from validated JWTs and generates a random organization UUID; a SQL transaction adds the organization, first admin and a provisioning audit row. It returns only the new UUID. A reused operator or admin token fails as a replay; files should be securely destroyed promptly and any disclosure treated as an incident.

To finish onboarding, configure the trusted IdP so that the initial admin receives the **new** organization UUID in the signed `organization_id` claim, plus the `tenant_admin` role. Then confirm `GET /api/v1/me` returns the intended organization. This last step is manual and remains open for automation in #14/#23.

**Development test only:** `tests/integration/provisioning-smoke.sh` obtains signed tokens from a dedicated local Keycloak password-grant test client (not production). GitHub Actions runs this flow plus replay and privilege-denial checks. `PROVISIONING_ALLOW_HTTP_LOOPBACK=true` is accepted only when the issuer URL is loopback HTTP; the default is HTTPS-only. Do not use the seeded demo passwords or password-grant mode in production.

## Required production controls
The SQL issuer/subject fields demonstrate which signed token claims the CLI verified, not the real-time revocation status or legally sealed authentication evidence. See #23 for IdP introspection, strong identity continuity, short-lived approval, tamper-evident approval trail and full operational key/role separation. For PostgreSQL deployments create restricted logins through migration/change approval with least-privilege credential injection; the development `setup-local-db-roles.sh` must **never** be executed with production credentials.

## Mandatory live token-status checks (#26)
The operator CLI checks each signed access token again through the trusted Keycloak RFC 7662 introspection endpoint **immediately before creating the organization**. The confidential client must be a permitted audience (`aud`) of both operator and first-admin tokens, especially on Keycloak 26.4.12+; do not enable compatibility relaxations. A returned `active=false`, mismatched issuer/subject/audience/role, unreachable IdP or missing credentials prevents any DB write. This is **not** an active-user directory/role lookup, human approval or an atomic cross-system revocation guarantee. See [ADR 0008](../adr/0008-live-keycloak-introspection.md) and issue #25. The local realm has a fake client secret for CI only; **never reuse the secret or the password-grant fixture in production**.
