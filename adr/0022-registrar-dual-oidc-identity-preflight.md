# ADR 0022 — Dual-principal registrar/reviewer OIDC preflight, without credential or SQL authority

Status: **accepted for an isolated non-authorizing identity guard** (2026-11-15). Scope #47, child of #46/#44/#38. References ADR 0010 (live effective-role directory), ADR 0011 (signed ACR and recency; **no disposable exception**), ADR 0021 (V013/V014 owner-controlled registration intent and NOLOGIN registrar group).

## Threat and trust boundary

A successful signed JWT + RFC7662 `active=true` + fresh directory roles does not make a WebAuthn credential, prove an independent registrar physically approved enrollment, or authorize SQL mutations. JWT roles may be stale after token creation; introspection is a server-side authorization snapshot and current directory checks are an additional separate snapshot. A malicious user may attempt to reuse a bearer, impersonate a registrar via a supplied name, mix OIDC audiences or act as reviewer and registrar at the same time. IdP failure must deny. The V013 SQL intent is intentionally unconsumable; an OIDC status check **cannot** change that guarantee.

## Decision

1. Provide a pure .NET 10 `ReviewerCredentialRegistrarIdentityGate` in the business layer, **not wired to API, PWA, CLI or any SQL executor**. Dependencies MUST be real external cryptographic `IVerifiedOidcTokenSource` (the production `OidcAccessTokenVerifier`), `ILiveOidcTokenStatus` (Keycloak RFC7662 adapter), and `ICurrentOidcAccountDirectory` (Keycloak Admin REST role and enabled-account adapter). Local unit tests inject fakes for negative external-state cases, and positive tests exercise real RS256 signing+verification using test-only keys. This is a *preflight*, never a registration approval.
2. Pin **exact** issuer and two **different** audiences in an immutable constructor policy: registrar `temporalmark-credential-registrar` and reviewer `temporalmark-approval` are the intended deployment settings. Require signed role `platform_credential_registrar` and `platform_approver` respectively, and both the roles and audience/issuer/subject to match **fresh** RFC7662 token introspection. A fresh independent current-directory lookup per principal must return `enabled=true` and the exact respective *effective realm role*. Never replace these checks with client headers or stale JWT roles.
3. Require two distinct bearer strings and two distinct valid subjects, with exact reviewer subject tied to a **server-trusted expected scope**. If a pending organization request is involved, caller must also supply the *original SQL-fetched* operator and initial-admin subjects as excluded identities; reject both registrar and reviewer when either equals one of these, and reject registrar==reviewer. Exclusions are not themselves authenticated data; the future caller must fetch them independently from privileged database scope.
4. Reuse the established `ApprovalAuthenticationPolicy` with **`allowPasswordOnlyDisposableLocalFixture:false`** for BOTH principals; pinned exact required ACR, numeric `auth_time` and `iat`, 1–120 second freshness and chronology checks. Never silently accept a password-grant or configurable exemption, even on loopback CI. A signed ACR remains only an IdP assertion: production needs independent Keycloak authentication-flow governance and real browser MFA evidence.
5. Deny on null/oversized/whitespace bearer, equal bearer values, malformed/untrusted pinned config, wrong signed scope, invalid live state, missing directory data, disabled principal, role removal, mismatched identity or upstream failure. **Do not cache** positive introspection/directory results. The function returns only ephemeral, no-secret `RegistrarIdentityPreflight` fields; it neither persists/returns access tokens nor creates an approved credential/nonce.
6. No new registration executor, SQL role membership or login, production WebAuthn key/trust store, external signer validation, public endpoint, human consent, approval/rejection, migration or privilege update is authorized by this ADR. #46 still needs true live Keycloak registrar configuration and independently authenticated SQL issuance integration, with time-of-check/time-of-use and replay control. #44 still needs maintained FIDO2 attestation, unique active credential registry, revocation and actual independent signoff. #38 still needs human-held signed decision and revocation of unsigned direct SQL approve/reject grants. #17/#13 WORM/legal gates remain open.

## TDD and release

RED signed-RS256+adversarial xUnit contract **before** the helper exists, then GREEN code; four-job exact-main-head GitHub CI before closing the child #47. An in-memory independent test signing key is **not** proof of a production IdP, real MFA or true independently held human identities.

## References

- RFC 7662 token introspection, especially active/aud/security considerations: https://www.rfc-editor.org/rfc/rfc7662
- OIDC Core 1.0 ACR and auth_time: https://openid.net/specs/openid-connect-core-1_0.html
- Keycloak current user and effective roles: https://www.keycloak.org/docs/latest/server_admin/
- Previous [ADR 0010](0010-keycloak-current-directory-check.md), [ADR 0011](0011-signed-approval-authentication-assurance.md) and [ADR 0021](0021-registrar-only-unconsumable-credential-intent.md).
