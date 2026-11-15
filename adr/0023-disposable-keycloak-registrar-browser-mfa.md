# ADR 0023 — Disposable browser-MFA registrar and reviewer live OIDC verification

Status: **accepted as a CI-only identity assurance test**, 2026-11-15. Scope #48 child of #46/#44/#38. Read ADR 0010 (current roles), 0011 (pinned ACR and fresh signed auth_time), 0013 (real browser password/TOTP Code+PKCE) and 0021–0022 (unconsumable registrar intent, dual OIDC preflight).

## Context

ADR 0022 / #47 validates real RS256-signed *synthetic* JWTs in unit tests but uses simulated RFC7662 and current-directory results. An attacker can reuse a bearer, and a role removed after token issuance may survive in token claims. A test of the actual Keycloak OTP browser ceremony and administrative directory state is needed to verify the no-MFA-downgrade behavior for the **different** registrar role. Keycloak's `acr` still reflects configured IdP policy; independent physical possession/human review is never demonstrated by CI alone.

## Narrow design decision

1. Expand ONLY the disposable Keycloak `temporalmark-mfa-ci` realm and CI scripts with a distinct fixed-ID registrar principal (`platform_credential_registrar`), a separate public OIDC authorization-code S256 PKCE client with audience `temporalmark-credential-registrar`, and a second bearer audience. Require the existing Keycloak configured LoA=2 password + **real TOTP** flow, including a clean browser login **after** TOTP enrollment. Wrong OTP cannot obtain authorization code. No password grant or silent `acr` fabrication.
2. CI runs a registrar browser MFA flow in addition to the existing, independent reviewer MFA browser flow; both signed Keycloak JWTs are held in ephemeral runner-owned `0600` files, with no traces/videos/screenshots or secrets logged; shell trap removes tokens. Keep issuance in the same disposable realm but **distinct** user subjects/audiences. Validate actual JWKS signatures, issuer, subject, role, audience, numeric auth_time and claimed ACR.
3. Add separate *disposable-only* read-only Keycloak Admin REST client with `realm-management/view-users,view-realm,query-users` (not manage-users) and a restricted confidential introspection client. A CI-only setup script grants these roles using existing disposable master admin creds, never for any production realm. Both browser tokens include a scoped audience mapper for this introspection client; real `KeycloakTokenIntrospector` and `KeycloakCurrentAccountDirectory` are invoked by the production business-layer identity gate. **No registrar login, membership or SQL credential is created by the setup script.**
4. ADR 0022's `RegistrarIdentityGatePolicy` has a strict HTTPS issuer by default. To exercise the existing local HTTP Keycloak Docker fixture only, allow an explicit **hardcoded** test option restricted to `http://localhost:8081/realms/temporalmark-mfa-ci`. Arbitrary HTTP URLs and any production issuer still fail closed. Production deployments MUST use HTTPS; the Docker-only exception does NOT provide production-grade security.
5. After a positive *real* signed+live+directory gate, CI temporarily removes the registrar's `platform_credential_registrar` current realm role or disables the account using the disposable-only admin credential; a previously valid access token MUST fail current directory validation. No caching or JWT-only role fallback. Restore is unnecessary because container volumes are destroyed.
6. No WebAuthn `navigator.credentials.create()` event, key, COSE attestation, FIDO2 verifier, registered credential, one-time registrar intent consumption, registration API, SQL role membership, human device custody, tenant decision or qualified timestamp is added. #46 still needs independent real registrar production MFA configuration, secured service credentials and guarded issuance; #44 needs enrolled signed keys and revoke/recovery; #38 needs signature-gated one-time approved decision and old SQL grants removed. CI success cannot certify legal WORM (#17) or QTSP status (#13).

## TDD and release criteria

Create failing RED browser and .NET checks while registrar fixture is still absent; then add minimal realm and CI fixtures + strict local test-only issuer option. Verify final commit's backend/frontend/Terraform/docker-smoke four job status success and record exact SHA before closing #48; do not silently mark a passing early push as success for a later final push. Never rewrite checksummed V001–V014. Neither on-prem nor Azure receives a production registrar fixture.

## References

- Keycloak 26.4 server administration guide: https://www.keycloak.org/docs/26.4.7/server_admin/
- Keycloak effective roles and admin RBAC: https://www.keycloak.org/docs/26.4.7/server_admin/index.html
- RFC7662 introspection: https://www.rfc-editor.org/rfc/rfc7662
- OIDC Core ACR/auth_time: https://openid.net/specs/openid-connect-core-1_0.html
