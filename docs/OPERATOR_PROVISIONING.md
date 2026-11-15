# Controlled OIDC organization enrollment (pilot)

**Only a restricted operator executable, not an HTTP self-registration feature.** Read [ADR 0007](../adr/0007-oidc-operator-provisioning.md), [ADR 0006](../adr/0006-tenant-bootstrap-and-admin-integrity.md) and #23 before using.

## Prerequisites
- Trusted OIDC discovery endpoint with valid signed keys (HTTPS; local Keycloak loopback HTTP only for an explicit development run).
- Independent authentication to the SAME issuer for two DISTINCT people:
  (1) platform operator with signed `platform_provisioner` role, audience `temporalmark-provisioner`; (2) intended first tenant admin with signed `tenant_admin` role, audience `temporalmark-api`.
- Fresh, non-replayed OIDC access tokens (`iat` within 5 minutes), with audience, issuer, `sub`, signature and expiry. Supported roles: direct `role` or `roles` claims.
- Database migrated to `V007`, with a dedicated `temporalmark_provisioner` SQL login assigned only to `temporalmark_provisioner_group`. Runtime API credential must be separate and cannot EXECUTE privileged bootstrap routines.
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
# These connection strings must be read from the approved operator secret vault.
export TEMPORALMARK_PROVISIONING_DB='<restricted-operator-SQL-login>'
export TEMPORALMARK_APPROVER_DB='<independent-approver-SQL-login>'

# 1. Operator requests a tenant, but cannot activate it.
dotnet run --project src/backend/applications/TemporalMark.Provisioner -- \
  request --organization-name 'Approved Customer Name' \
  --operator-token-file /restricted/operator.jwt \
  --first-admin-token-file /restricted/initial-admin.jwt
# Output: Approval requested: <organization/request UUID>

# 2. Different, separately authorized approver MUST independently review the
# exact organization, issuer and stable OIDC subject IDs before confirming.
dotnet run --project src/backend/applications/TemporalMark.Provisioner -- \
  approve --request-id '<UUID-from-step-1>' \
  --organization-name 'Approved Customer Name' \
  --expected-initial-admin-sub '<IdP-verified-initial-admin-sub>' \
  --expected-operator-sub '<IdP-verified-operator-sub>' \
  --approver-token-file /restricted/approver.jwt

# 3. Operator presents currently valid, live tokens again and consumes approval.
dotnet run --project src/backend/applications/TemporalMark.Provisioner -- \
  complete --request-id '<UUID-from-step-1>' \
  --organization-name 'Approved Customer Name' \
  --operator-token-file /restricted/operator.jwt \
  --first-admin-token-file /restricted/initial-admin.jwt
# Output: Organization created: <same UUID>
```

The pending request expires exactly **five minutes** after it was created in the pilot. Rejected, incomplete, expired or mismatched approvals cannot produce a tenant; used approvals cannot be reused. PostgreSQL enforces different subjects and isolated SQL roles, and the completion transaction also links the pilot audit record to the approval. **The CLI does not provide an independent request-review UI, current directory role lookup, MFA step-up, legally sealed audit, or accredited approval process.** Complete operator-guided provisioning policy under issue #27 and #25.

A separate IdP administrator must still map the newly created `organization_id` to the first admin. Check signed claims and `GET /api/v1/me`; automated invitations and multi-org selection remain #14.

## Mandatory live token-status checks (#26)
The operator CLI checks each signed access token again through the trusted Keycloak RFC 7662 introspection endpoint **immediately before creating the organization**. The confidential client must be a permitted audience (`aud`) of both operator and first-admin tokens, especially on Keycloak 26.4.12+; do not enable compatibility relaxations. A returned `active=false`, mismatched issuer/subject/audience/role, unreachable IdP or missing credentials prevents any DB write. This is **not** an active-user directory/role lookup, human approval or an atomic cross-system revocation guarantee. See [ADR 0008](../adr/0008-live-keycloak-introspection.md) and issue #25. The local realm has a fake client secret for CI only; **never reuse the secret or the password-grant fixture in production**.

## Mandatory current-account and effective-role checks (#30)

The CLI additionally obtains a distinct, short-lived service-account bearer token from the **same pinned Keycloak realm** and queries the account status plus *current effective realm roles* through the Keycloak Admin REST API, separately from JWT/introspection. Every request, approval and completion performs fresh checks for the intended user(s). The dedicated confidential directory client must be granted only the required **read-only** `realm-management` permissions (`view-users`, `view-realm`, optionally `query-users` according to approved Keycloak configuration); no `realm-admin` or `manage-users`. An unavailable directory, missing role, disabled user, wrong ID/issuer, expired/invalid service credential or HTTP failure blocks all provisioning actions. Do **not** reuse the development service account, its demo secret, or the test setup script in production. The Keycloak directory check is independent of token claims but not a signed assertion; MFA, actual human signoff, policy attestation and TOCTOU reconciliation remain outstanding. See [ADR 0010](../adr/0010-keycloak-current-directory-check.md) and #27/#25.
