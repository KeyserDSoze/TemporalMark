# ADR 0012 — Provenienza dell'autenticazione dell'approvatore

Status: Accepted for pilot (2026-11-15); **not evidence of actual MFA or qualified timestamping**.
Related: ADR 0009–0011, #17, #23, #27, #31, #33.

## Problem
The approval CLI already validates cryptographically signed `acr`, `auth_time` and token `iat`, but PostgreSQL previously recorded only a token SHA-256 and an approver subject. Approved-ACR claims and the disposable password-grant test exception were indistinguishable, while the restricted approver login could call the older seven-argument SQL function without provenance.

## Decision
- `IApprovalAuthenticationPolicy.Require` returns `ApprovalAuthenticationEvidence` with `Kind`, `Context`, `AuthenticationTimeUnix`, `PolicyId`. The **strong branch** is `OIDC_ACR_ASSERTED` with the configured ACR and recent signed `auth_time`; it is merely an IdP assertion, **NOT a certificate that MFA happened**. The explicit hardcoded local test exception returns `DISPOSABLE_PASSWORD_ONLY` with null ACR/time, even if a local token contains misleading claims.
- New immutable `V008__approval_assurance_provenance.sql` adds these bounded fields to pending approval requests. The approval is already linked to the eventual organization/first administrator through the existing event FK; no raw JWT, OTP or secrets are stored.
- Restricted SQL approvers lose EXECUTE on the old seven-argument `approve_enrollment` routine, gaining only the ten-argument function requiring provenance. That function checks the current authentication time and accepts the test classification only for the **exact** `http://localhost:8081/realms/temporalmark` issuer plus hardcoded fixture approver UUID. The SQL credential is still a critical trust boundary; database owners can perform break-glass operations.
- Historical approved rows are backfilled as `LEGACY_UNVERIFIED` instead of fabricating MFA metadata. Previously consumed historical rows remain intact. A new trigger prevents newly completing an unconsumed legacy-unverified request.
- TDD: negative unit/SQL tests reject missing data, weak context, spoofed test classification and legacy-function access. Keycloak CI checks its password-grant test is persisted **as non-MFA**, never signed MFA. All seven earlier migrations remain immutable.

## Limitations
- Keycloak **must** be separately configured and verified with genuine browser OTP/WebAuthn step-up and independent user confirmation before production approval: #31 stays OPEN.
- `acr` is an assertion, not proof that two different factors occurred. Current roles and token state can change between the read and SQL commit.
- The pilot table is not tamper-proof, independently signed or WORM (#17). No production secret-management, legal assurance, CAB/AgID qualification or QTSP status is asserted (#13).
- Microsoft Entra requires its own provider and assurance model (#28).

## References
- https://openid.net/specs/openid-connect-core-1_0.html
- https://www.keycloak.org/docs/26.4.7/server_admin/
- https://www.postgresql.org/docs/17/sql-grant.html
