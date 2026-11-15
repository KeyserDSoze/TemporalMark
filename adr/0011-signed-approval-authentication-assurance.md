# ADR 0011 — Cryptographically validated approval ACR and authentication freshness (pilot)

Status: Accepted for pilot implementation, **not MFA-qualified**, 2026-11-15.

Related: ADR 0007–0010; #25, #27, #31, #32.

## Problem

A signed Keycloak token carrying a `platform_approver` role, an active RFC 7662 result and a current realm role do not establish **how recently or how strongly** the approver authenticated. A password-only (or stale) session can authorize an irreversible tenant onboarding operation. Likewise, an `acr` token claim only represents the IdP's configured authentication level; it is not by itself independent proof that the claimed level represents real MFA.

## Decision

1. `OidcAccessTokenVerifier` parses `acr`, numeric `auth_time` and `iat` only **after** validating the JWT signature, pinned issuer, audience, expiry, 300-second issuance freshness and allowed signature algorithms. It returns these claims as part of `VerifiedOidcToken`, without allowing callers to supply trusted assurance metadata.
2. `OrganizationApprovalWorkflow.ApproveAsync` invokes a **mandatory** `IApprovalAuthenticationPolicy` dependency after validating the approver's issuer, subject and signed `platform_approver` role. It rejects absent, mismatched, weak or invalid authentication context **before** live introspection, independent current-directory lookup or SQL approval.
3. The production implementation `ApprovalAuthenticationPolicy` requires an explicitly pinned exact `PROVISIONING_APPROVER_REQUIRED_ACR` (max 255 chars), refuses empty, `0`, `1`, `pwd`, `password`, `basic` or untrimmed values, requires numeric `auth_time` and `iat`, rejects authentication older than 120 seconds or in the future beyond 30 seconds, and ensures `auth_time` does not postdate token issuance by more than 30 seconds. No fallback based only on `amr` or roles.
4. **Operational prerequisite:** the security team MUST verify, configure and audit the pinned ACR-to-LoA mapping against an actual Keycloak browser or device flow that requires a second factor. The policy checks the cryptographically signed assertion, **not whether Keycloak's configuration genuinely enforced two factors**. A symbolic ACR without verified IdP configuration is insufficient for a production release.
5. Existing disposable CI Keycloak uses a **password grant** without MFA. To retain regression coverage for the three-person, DB-enforced onboarding workflow, a deliberately named `PROVISIONING_DEVELOPMENT_PASSWORD_GRANT_NO_MFA=true` exception is allowed ONLY when `PROVISIONING_ALLOW_HTTP_LOOPBACK=true`, pinned issuer is **exactly** `http://localhost:8081/realms/temporalmark`, and the verified approver subject is the hardcoded `00000000-0000-0000-0000-000000000004` CI test identity. The production issuer cannot take this branch. This fixture tests *everything except authentication assurance* and must never be used to claim MFA effectiveness.

## Residual risks and release gates

- The signed ACR could be misconfigured at the identity provider; actual browser login with password+OTP/WebAuthn, step-up `claims`/LoA, `auth_time` emission, test of revoked/expired factors and independent assurance evidence remain issue #31.
- A currently valid strong approver bearer token or privileged SQL credentials could still be stolen. Strong human consent, a reviewer-facing confirmation of exact organization/identity data, proof-of-possession or signed one-time decision and non-repudiation are not implemented (#31).
- The service cannot transact atomically across Keycloak and PostgreSQL. ACR, authentication age, role status and approval are snapshots separated by a time-of-check/time-of-use window.
- Password grant, all local secrets, public HTTP localhost, the dev exception and unsealed SQL audit are **development-only**. Production requires vault credentials, TLS and secured client authentication, approved MFA configurations, access monitoring, policy assurance reviews and independent WORM/signed evidence (#17).
- Microsoft Entra integration (#28) needs its own validated ACR/authentication context and account/role adapter. Do not treat Keycloak claims or Admin REST endpoints as universal.
- Nothing in this ADR certifies TemporalMark as a Qualified Trust Service Provider or guarantees timestamp legal qualification (#13).

## Authoritative documentation

- Keycloak Server Administration Guide, ACR to LoA mapping and step-up browser authentication: https://www.keycloak.org/docs/latest/server_admin/
- OIDC Core 1.0, `acr` and `auth_time` claim semantics: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 7662 token introspection: https://www.rfc-editor.org/rfc/rfc7662
